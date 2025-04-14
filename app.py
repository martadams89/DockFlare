import os
import sys
import logging
import re
import json
import threading
import time
from datetime import datetime, timedelta, timezone
import random

import docker
from docker.errors import NotFound, APIError
# Updated import: Added render_template, flash, session (flash might be useful later)
from flask import Flask, jsonify, render_template, redirect, url_for, request, flash, session
from dotenv import load_dotenv
import requests

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s')
load_dotenv()

# Retry Config for CF PUT Tunnel Config
MAX_CF_UPDATE_RETRIES = 3
CF_UPDATE_RETRY_DELAY = 2
CF_UPDATE_BACKOFF_FACTOR = 2

# Cloudflare Config
CF_API_TOKEN = os.getenv('CF_API_TOKEN')
TUNNEL_NAME = os.getenv('TUNNEL_NAME')
CF_ACCOUNT_ID = os.getenv('CF_ACCOUNT_ID')
# CF_ZONE_ID is the *default* zone ID
CF_ZONE_ID = os.getenv('CF_ZONE_ID')
CF_API_BASE_URL = "https://api.cloudflare.com/client/v4"
CF_HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json",
}
logging.info(f"[DEBUG] CF_HEADERS created: Authorization Header starts with 'Bearer {str(CF_API_TOKEN)[:5]}...'")

# App Config
LABEL_PREFIX = os.getenv('LABEL_PREFIX', 'cloudflare.tunnel')
# Default grace period now 2 hours (7200 seconds), can be overridden by env var or state file
GRACE_PERIOD_SECONDS = int(os.getenv('GRACE_PERIOD_SECONDS', 7200))
CLEANUP_INTERVAL_SECONDS = int(os.getenv('CLEANUP_INTERVAL_SECONDS', 300))
STATE_FILE_PATH = os.getenv('STATE_FILE_PATH', '/app/data/state.json')

# Cloudflared Agent Config
CLOUDFLARED_CONTAINER_NAME = os.getenv('CLOUDFLARED_CONTAINER_NAME', f"cloudflared-agent-{TUNNEL_NAME}")
CLOUDFLARED_IMAGE = "cloudflare/cloudflared:latest"
CLOUDFLARED_NETWORK_NAME = os.getenv('CLOUDFLARED_NETWORK_NAME', 'cloudflare-net')

# Environment Variable Checks
if not CF_API_TOKEN or not TUNNEL_NAME or not CF_ACCOUNT_ID:
    logging.error("FATAL: Missing required environment variables (CF_API_TOKEN, TUNNEL_NAME, CF_ACCOUNT_ID)")
    sys.exit(1)
if not CF_ZONE_ID:
    logging.warning("CF_ZONE_ID environment variable is not set. DNS management will ONLY work if containers specify 'cloudflare.tunnel.zonename' label or rules are added manually with a zone name.")


# Docker Client Setup
try:
    docker_client = docker.from_env(timeout=10)
    docker_client.ping()
    logging.info("Successfully connected to Docker daemon.")
except Exception as e:
    logging.error(f"FATAL: Failed to connect to Docker daemon: {e}")
    docker_client = None

# Global State
tunnel_state = { "name": TUNNEL_NAME, "id": None, "token": None, "status_message": "Initializing...", "error": None }
cloudflared_agent_state = { "container_status": "unknown", "last_action_status": None }
managed_rules = {} # Stores rule details including 'zone_id' and 'type' ('docker' or 'manual')
zone_id_cache = {} # Cache for zone name -> zone ID lookups
state_lock = threading.Lock()
stop_event = threading.Event()


# --- load_state ---
# UPDATED: Handle loading grace period and default rule type
def load_state():
    global managed_rules
    global GRACE_PERIOD_SECONDS

    # Initialize with default/env value
    current_default_grace_period = GRACE_PERIOD_SECONDS
    logging.info(f"Initial default GRACE_PERIOD_SECONDS: {current_default_grace_period}")

    state_dir = os.path.dirname(STATE_FILE_PATH)
    if not os.path.exists(state_dir):
        try: os.makedirs(state_dir, exist_ok=True); logging.info(f"Created directory for state file: {state_dir}")
        except OSError as e: logging.error(f"FATAL: Cannot create state dir {state_dir}: {e}."); managed_rules = {}; return

    if not os.path.exists(STATE_FILE_PATH):
        logging.info(f"State file '{STATE_FILE_PATH}' not found, starting fresh."); managed_rules = {}; return

    try:
        with open(STATE_FILE_PATH, 'r') as f: loaded_data = json.load(f)

        # --- Load Settings ---
        loaded_settings = loaded_data.get("settings", {})
        saved_grace_period = loaded_settings.get("grace_period_seconds")
        if saved_grace_period is not None:
            try:
                saved_grace_period_int = int(saved_grace_period)
                if saved_grace_period_int >= 0: GRACE_PERIOD_SECONDS = saved_grace_period_int; logging.info(f"Loaded GRACE_PERIOD_SECONDS from state: {GRACE_PERIOD_SECONDS}")
                else: logging.warning(f"Invalid grace period in state: {saved_grace_period}. Using default: {current_default_grace_period}"); GRACE_PERIOD_SECONDS = current_default_grace_period
            except (ValueError, TypeError): logging.warning(f"Invalid grace period type in state: {saved_grace_period}. Using default: {current_default_grace_period}"); GRACE_PERIOD_SECONDS = current_default_grace_period
        else: logging.info("No grace period in state settings. Using default."); GRACE_PERIOD_SECONDS = current_default_grace_period

        # --- Load Rules ---
        loaded_rules = loaded_data.get("rules", {})
        parsed_rules = {}
        for hostname, rule in loaded_rules.items():
            # Parse delete_at
            if rule.get("delete_at") and isinstance(rule.get("delete_at"), str):
                try: rule["delete_at"] = datetime.fromisoformat(rule["delete_at"].replace('Z', '+00:00')) if rule["delete_at"].endswith('Z') else datetime.fromisoformat(rule["delete_at"]).replace(tzinfo=timezone.utc)
                except ValueError: logging.warning(f"Could not parse delete_at for {hostname}. Setting None."); rule["delete_at"] = None
            elif not isinstance(rule.get("delete_at"), datetime): rule["delete_at"] = None
            # Ensure zone_id field exists
            if "zone_id" not in rule: logging.warning(f"Rule {hostname} missing 'zone_id'."); rule["zone_id"] = None
            # Ensure type field exists (default to 'docker' for old state files)
            if "type" not in rule: logging.warning(f"Rule {hostname} missing 'type', defaulting to 'docker'."); rule["type"] = "docker"
            parsed_rules[hostname] = rule
        managed_rules = parsed_rules

        logging.info(f"Loaded state for {len(managed_rules)} rules from {STATE_FILE_PATH}")

    except (json.JSONDecodeError, IOError, OSError) as e:
        logging.error(f"Error loading state from {STATE_FILE_PATH}: {e}. Starting fresh.", exc_info=True)
        managed_rules = {}
        GRACE_PERIOD_SECONDS = current_default_grace_period # Revert on load error


# --- save_state ---
# UPDATED: Save structured state with settings and rules
def save_state():
    state_to_save = { "settings": { "grace_period_seconds": GRACE_PERIOD_SECONDS }, "rules": {} }
    for hostname, rule in managed_rules.items():
        rule_copy = rule.copy()
        if rule_copy.get("delete_at") and isinstance(rule_copy["delete_at"], datetime):
            rule_copy["delete_at"] = rule_copy["delete_at"].astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        if "zone_id" not in rule_copy: rule_copy["zone_id"] = None
        if "type" not in rule_copy: rule_copy["type"] = "docker" # Should always have type now
        state_to_save["rules"][hostname] = rule_copy
    try:
        state_dir = os.path.dirname(STATE_FILE_PATH)
        if not os.path.exists(state_dir):
            try: os.makedirs(state_dir, exist_ok=True); logging.info(f"Created dir {state_dir} for state.")
            except OSError as e: logging.error(f"Cannot create state dir {state_dir}: {e}. Save failed."); return
        temp_file_path = STATE_FILE_PATH + ".tmp"
        with open(temp_file_path, 'w') as f: json.dump(state_to_save, f, indent=2)
        os.replace(temp_file_path, STATE_FILE_PATH)
        logging.debug(f"Saved state ({len(managed_rules)} rules, grace={GRACE_PERIOD_SECONDS}s) to {STATE_FILE_PATH}")
    except (IOError, OSError) as e: logging.error(f"Error saving state to {STATE_FILE_PATH}: {e}", exc_info=True)


# --- cf_api_request ---
# No changes needed
def cf_api_request(method, endpoint, json_data=None, params=None):
    # ... (previous implementation) ...
    url = f"{CF_API_BASE_URL}{endpoint}"; error_msg = None
    try:
        request_headers = CF_HEADERS.copy(); logging.info(f"API Request: {method} {url} P={params} D={json_data}")
        response = requests.request(method, url, headers=request_headers, json=json_data, params=params, timeout=30)
        response.raise_for_status(); logging.info(f"API Response Status: {response.status_code}")
        if response.status_code == 204 or not response.content: return {"success": True, "result": None}
        try:
            response_data = response.json(); logging.debug(f"API Response Body (500): {str(response_data)[:500]}")
            if isinstance(response_data, dict) and 'success' in response_data:
                 if response_data['success']: return response_data
                 else:
                      cf_errors = response_data.get('errors', [])
                      if cf_errors and isinstance(cf_errors[0], dict): error_msg = f"API Error: {cf_errors[0].get('message', 'Unknown')}"
                      else: error_msg = f"API fail, no details: {response_data}"
                      logging.error(f"API Fail ({method} {url}): {error_msg} - Full: {cf_errors}"); raise requests.exceptions.RequestException(error_msg, response=response)
            else: logging.warning(f"API JSON unexpected format: {str(response_data)[:200]}"); raise requests.exceptions.RequestException("Unexpected JSON format", response=response)
        except json.JSONDecodeError: logging.error(f"API invalid JSON: {response.text[:200]}"); raise requests.exceptions.RequestException("Invalid JSON response", response=response)
    except requests.exceptions.RequestException as e:
        if error_msg is None:
            logging.error(f"API Request Failed: {method} {url}"); error_msg = f"Request Exception: {e}"
            if e.response is not None:
                try:
                    error_data = e.response.json(); logging.error(f"Response Body: {error_data}"); cf_errors = error_data.get('errors', [])
                    if cf_errors and isinstance(cf_errors[0], dict): error_msg = f"API Error: {cf_errors[0].get('message', 'Unknown')}"
                    else: error_msg = f"HTTP {e.response.status_code} - {e.response.text[:100]}"
                except: error_msg = f"HTTP {e.response.status_code} - {e.response.text[:100]}"
            else: logging.error(f"No response received: {e}")
        if "cfd_tunnel" in endpoint and tunnel_state.get("id") is None and "token" not in endpoint: tunnel_state["error"] = error_msg
        raise requests.exceptions.RequestException(error_msg, response=e.response)

# --- get_zone_id_from_name ---
# No changes needed
def get_zone_id_from_name(zone_name):
    # ... (previous implementation) ...
    global zone_id_cache; if not zone_name: logging.warning("get_zone_id: empty zone_name."); return None
    with state_lock: cached_id = zone_id_cache.get(zone_name)
    if cached_id: logging.debug(f"Zone ID '{zone_name}' from cache: {cached_id}"); return cached_id
    logging.info(f"Zone ID '{zone_name}' not cached. Querying API...")
    endpoint = "/zones"; params = {"name": zone_name, "status": "active"}
    try:
        response_data = cf_api_request("GET", endpoint, params=params); results = response_data.get("result", [])
        if results and len(results) == 1:
            zone_id = results[0].get("id"); zone_actual_name = results[0].get("name")
            if zone_id and zone_actual_name == zone_name:
                logging.info(f"Found Zone ID for '{zone_name}': {zone_id}")
                with state_lock: zone_id_cache[zone_name] = zone_id
                return zone_id
            else: logging.error(f"API name mismatch for zone '{zone_name}': {results[0]}"); return None
        elif results: logging.error(f"Multiple zones match name '{zone_name}'. Ambiguous."); return None
        else: logging.warning(f"No active zone found matching '{zone_name}'."); return None
    except requests.exceptions.RequestException as e: logging.error(f"API error zone lookup '{zone_name}': {e}"); return None
    except Exception as e: logging.error(f"Unexpected error zone lookup '{zone_name}': {e}", exc_info=True); return None

# --- find_tunnel_via_api / get_tunnel_token_via_api / create_tunnel_via_api ---
# No changes needed
def find_tunnel_via_api(name): # ... (previous implementation) ...
    logging.info(f"[DEBUG] Entering find_tunnel_via_api for '{name}'")
    endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel"; params = {"name": name, "is_deleted": "false"}
    try:
        response_data = cf_api_request("GET", endpoint, params=params); tunnels = response_data.get("result", [])
        if tunnels: tunnel = tunnels[0]; tunnel_id = tunnel.get("id")
        else: logging.info(f"Tunnel '{name}' not found."); logging.info(f"[DEBUG] Exit find - Not found"); return None, None
        if tunnel_id: logging.info(f"Found tunnel '{name}' ID: {tunnel_id}."); token = get_tunnel_token_via_api(tunnel_id); logging.info(f"[DEBUG] Exit find - Found ID/Token: {bool(token)}"); return tunnel_id, token
        else: logging.warning(f"Tunnel '{name}' found but no ID: {tunnel}"); logging.info(f"[DEBUG] Exit find - Found but no ID"); return None, None
    except requests.exceptions.RequestException as e: logging.error(f"API error finding tunnel '{name}': {e}"); logging.info(f"[DEBUG] Exit find - RequestException"); return None, None
    except Exception as e: logging.error(f"Unexpected error finding tunnel '{name}': {e}", exc_info=True); tunnel_state["error"] = f"Unexpected find tunnel: {e}"; logging.info(f"[DEBUG] Exit find - Exception"); return None, None

def get_tunnel_token_via_api(tunnel_id): # ... (previous implementation) ...
    logging.info(f"[DEBUG] Entering get_tunnel_token_via_api ID '{tunnel_id}'")
    endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}/token"; url = f"{CF_API_BASE_URL}{endpoint}"
    try:
        request_headers = {"Authorization": f"Bearer {CF_API_TOKEN}"}; logging.info(f"API Request: GET {url} (for token)")
        response = requests.request("GET", url, headers=request_headers, timeout=30); response.raise_for_status(); token = response.text.strip()
        if not token or len(token) < 50: logging.error(f"Invalid token format for {tunnel_id}."); logging.info(f"[DEBUG] Exit get_token - Invalid Format"); raise ValueError("Invalid token format")
        logging.info(f"Got token via API for {tunnel_id}"); logging.info(f"[DEBUG] Exit get_token - Success"); return token
    except requests.exceptions.RequestException as e: error_msg = f"API Error get token {tunnel_id}: {e}"; logging.error(error_msg); tunnel_state["error"] = error_msg; logging.info(f"[DEBUG] Exit get_token - RequestException"); raise
    except Exception as e: logging.error(f"Unexpected get token {tunnel_id}: {e}", exc_info=True); tunnel_state["error"] = f"Unexpected get token: {e}"; logging.info(f"[DEBUG] Exit get_token - Exception"); raise

def create_tunnel_via_api(name): # ... (previous implementation) ...
    logging.info(f"[DEBUG] Entering create_tunnel_via_api for '{name}'")
    endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel"; payload = {"name": name, "config_src": "cloudflare"}
    try:
        response_data = cf_api_request("POST", endpoint, json_data=payload); result = response_data.get("result", {})
        tunnel_id = result.get("id"); token = result.get("token")
        if not tunnel_id or not token: logging.error(f"API create missing ID/Token: {result}"); logging.info(f"[DEBUG] Exit create - Missing ID/Token"); raise ValueError("Missing ID/Token")
        logging.info(f"Created tunnel '{name}' ID {tunnel_id}."); logging.info(f"[DEBUG] Exit create - Success"); return tunnel_id, token
    except requests.exceptions.RequestException as e: logging.error(f"API error creating tunnel '{name}': {e}"); logging.info(f"[DEBUG] Exit create - RequestException"); return None, None
    except Exception as e: logging.error(f"Unexpected create tunnel '{name}': {e}", exc_info=True); tunnel_state["error"] = f"Unexpected create: {e}"; logging.info(f"[DEBUG] Exit create - Exception"); return None, None

# --- initialize_tunnel ---
# No changes needed
def initialize_tunnel(): # ... (previous implementation) ...
    logging.info("[DEBUG] Entering initialize_tunnel")
    tunnel_state["status_message"] = f"Checking tunnel '{TUNNEL_NAME}'..."; tunnel_state["error"] = None; tunnel_id = None; token = None
    try:
        logging.info("[DEBUG] Calling find_tunnel_via_api...")
        tunnel_id, token = find_tunnel_via_api(TUNNEL_NAME)
        logging.info(f"[DEBUG] find returned: ID={tunnel_id}, Token={bool(token)}")
        if not tunnel_id and not tunnel_state.get("error"):
            tunnel_state["status_message"] = f"Tunnel '{TUNNEL_NAME}' not found. Creating..."; logging.info("[DEBUG] Calling create_tunnel_via_api...")
            tunnel_id, token = create_tunnel_via_api(TUNNEL_NAME)
            logging.info(f"[DEBUG] create returned: ID={tunnel_id}, Token={bool(token)}")
        if tunnel_id and token:
            tunnel_state["id"] = tunnel_id; tunnel_state["token"] = token; tunnel_state["status_message"] = "Tunnel setup complete (API)."; tunnel_state["error"] = None
            logging.info(f"Tunnel '{TUNNEL_NAME}' initialized. ID: {tunnel_id}")
        elif not tunnel_state.get("error"): tunnel_state["status_message"] = "Tunnel init failed."; tunnel_state["error"] = "Failed find/create tunnel/token."; logging.error(f"Tunnel init failed '{TUNNEL_NAME}'. No ID/Token.")
        else: tunnel_state["status_message"] = "Tunnel init failed (error)."; logging.error(f"Tunnel init failed '{TUNNEL_NAME}' due to API error: {tunnel_state['error']}")
        logging.info(f"[DEBUG] Exit initialize_tunnel - State: ID={tunnel_state.get('id')}, Token={bool(tunnel_state.get('token'))}, Err={tunnel_state.get('error')}")
    except Exception as e:
        logging.error(f"Unhandled init exception: {e}", exc_info=True)
        if not tunnel_state.get("error"): tunnel_state["error"] = f"Init unexpected: {e}"
        tunnel_state["status_message"] = "Tunnel init failed (unexpected error)."
        logging.info(f"[DEBUG] Exit initialize_tunnel - Unhandled Exception: {e}")

# --- get_current_cf_config / find_dns_record_id / create_cloudflare_dns_record / delete_cloudflare_dns_record ---
# No changes needed
def get_current_cf_config(): # ... (previous implementation) ...
    if not tunnel_state.get("id"): logging.warning("get_current_cf_config: No tunnel ID."); return None
    endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel/{tunnel_state['id']}/configurations"
    try:
        response_data = cf_api_request("GET", endpoint)
        if response_data and response_data.get("success"): result_data = response_data.get("result")
        else: logging.error(f"Get config API failed: {response_data}"); return None
        if isinstance(result_data, dict): config_data = result_data.get("config")
        elif result_data is None: logging.info("Get config result is null."); return {}
        else: logging.warning(f"Get config unexpected result format: {response_data}"); return {}
        if isinstance(config_data, dict): logging.debug(f"Fetched config: {config_data}"); return config_data
        elif config_data is None: logging.info("Fetched config is null."); return {}
        else: logging.warning(f"Get config unexpected type for 'config': {type(config_data)}."); return {}
    except requests.exceptions.RequestException as e: logging.error(f"API error get config: {e}"); tunnel_state["error"] = f"Failed get config: {e}"; return None
    except Exception as e: logging.error(f"Unexpected get config: {e}", exc_info=True); tunnel_state["error"] = f"Unexpected get config: {e}"; return None

def find_dns_record_id(zone_id, hostname, tunnel_id): # ... (previous implementation) ...
    if not zone_id or not hostname or not tunnel_id: logging.error("find_dns: Missing args."); return None
    expected_content = f"{tunnel_id}.cfargotunnel.com"; endpoint = f"/zones/{zone_id}/dns_records"; params = {"type": "CNAME", "name": hostname, "content": expected_content, "match": "all"}
    try:
        logging.info(f"Searching DNS: Z={zone_id}, N={hostname}, C={expected_content}")
        response_data = cf_api_request("GET", endpoint, params=params); results = response_data.get("result", [])
        if results: record_id = results[0].get("id")
        else: logging.info(f"No matching DNS for {hostname} in {zone_id}"); return None
        if record_id: logging.info(f"Found DNS ID {record_id} for {hostname} in {zone_id}"); return record_id
        else: logging.warning(f"DNS record found for {hostname} but no ID: {results[0]}"); return None
    except requests.exceptions.RequestException as e: logging.error(f"API error find DNS for {hostname}: {e}"); return None
    except Exception as e: logging.error(f"Unexpected find DNS for {hostname}: {e}", exc_info=True); return None

def create_cloudflare_dns_record(zone_id, hostname, tunnel_id): # ... (previous implementation) ...
    if not zone_id or not hostname or not tunnel_id: logging.error("create_dns: Missing args."); return None
    record_name = hostname; record_content = f"{tunnel_id}.cfargotunnel.com"; endpoint = f"/zones/{zone_id}/dns_records"
    payload = {"type": "CNAME", "name": record_name, "content": record_content, "ttl": 1, "proxied": True }
    try:
        existing_id = find_dns_record_id(zone_id, hostname, tunnel_id)
        if existing_id: logging.info(f"DNS for {hostname} in {zone_id} exists (ID: {existing_id})."); return existing_id
        logging.info(f"Creating DNS in {zone_id}: N={record_name}, C={record_content}")
        response_data = cf_api_request("POST", endpoint, json_data=payload); result = response_data.get("result", {})
        new_record_id = result.get("id")
        if new_record_id: logging.info(f"Created DNS for {hostname} in {zone_id}. ID: {new_record_id}"); return new_record_id
        else: logging.error(f"DNS create success but no ID for {hostname}: {result}"); return None
    except requests.exceptions.RequestException as e: logging.error(f"API error create DNS for {hostname}: {e}"); return None
    except Exception as e: logging.error(f"Unexpected create DNS for {hostname}: {e}", exc_info=True); return None

def delete_cloudflare_dns_record(zone_id, hostname, tunnel_id): # ... (previous implementation) ...
    if not zone_id or not hostname or not tunnel_id: logging.error("delete_dns: Missing args."); return False
    dns_record_id = find_dns_record_id(zone_id, hostname, tunnel_id)
    if not dns_record_id: logging.warning(f"DNS for {hostname} in {zone_id} not found to delete."); return True
    logging.info(f"Deleting DNS for {hostname} in {zone_id} (ID: {dns_record_id})")
    endpoint = f"/zones/{zone_id}/dns_records/{dns_record_id}"
    try:
        cf_api_request("DELETE", endpoint); logging.info(f"Deleted DNS for {hostname} (ID: {dns_record_id})."); return True
    except requests.exceptions.RequestException as e:
        if e.response is not None and e.response.status_code == 404: logging.warning(f"DNS {dns_record_id} not found during delete (404). OK."); return True
        logging.error(f"API error delete DNS {dns_record_id} for {hostname}: {e}"); return False
    except Exception as e: logging.error(f"Unexpected delete DNS {dns_record_id} for {hostname}: {e}", exc_info=True); return False

# --- update_cloudflare_config ---
# No changes needed
def update_cloudflare_config(): # ... (previous implementation) ...
    if not tunnel_state.get("id"): logging.warning("Cannot update CF config, tunnel ID missing."); return False
    final_ingress_rules = None; needs_api_update = False
    with state_lock:
        logging.info("Preparing potential CF tunnel config update...")
        desired_ingress_rules = []; catch_all_rule = {"service": "http_status:404"}
        for hn, rule in managed_rules.items():
            if rule.get("status") == "active":
                if rule.get("service"): desired_ingress_rules.append({"hostname": hn, "service": rule["service"]})
                else: logging.warning(f"Rule {hn} active missing service.")
        desired_ingress_rules.sort(key=lambda x: x.get("hostname", ""))
        logging.debug("Fetching current CF config for comparison..."); current_config = get_current_cf_config()
        if current_config is None: logging.error("Failed fetch CF config, aborting update."); return False
        current_cf_ingress = [r for r in current_config.get("ingress", []) if r.get("service") != catch_all_rule["service"]]
        def rule_to_canonical(rule): return tuple(sorted([(k, v) for k, v in rule.items() if k in ["hostname", "service"]]))
        try: current_cf_set = {rule_to_canonical(r) for r in current_cf_ingress if r.get("hostname") and r.get("service")}; desired_set = {rule_to_canonical(r) for r in desired_ingress_rules if r.get("hostname") and r.get("service")}
        except Exception as e: logging.error(f"Error creating canonical rule sets: {e}", exc_info=True); return False
        if current_cf_set == desired_set: logging.info("No changes in CF config needed."); needs_api_update = False
        else: logging.info("CF config change detected."); logging.debug(f"Current: {current_cf_set}"); logging.debug(f"Desired: {desired_set}"); needs_api_update = True; final_ingress_rules = desired_ingress_rules + [catch_all_rule]
    if needs_api_update and final_ingress_rules is not None:
        endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel/{tunnel_state['id']}/configurations"; payload = {"config": {"ingress": final_ingress_rules}}; last_exception = None
        for attempt in range(MAX_CF_UPDATE_RETRIES + 1):
            try: logging.info(f"Pushing CF config (Attempt {attempt + 1}/{MAX_CF_UPDATE_RETRIES + 1})..."); cf_api_request("PUT", endpoint, json_data=payload); logging.info("Successfully updated CF tunnel config."); cloudflared_agent_state["last_action_status"] = f"CF config updated {datetime.now(timezone.utc).isoformat()}"; return True
            except requests.exceptions.RequestException as e: last_exception = e; status_code = e.response.status_code if e.response is not None else None; logging.warning(f"CF API update attempt {attempt + 1} failed: {e} (Status: {status_code})"); is_retryable = isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)) or status_code in [429, 500, 502, 503, 504]
            except Exception as e: last_exception = e; logging.error(f"Unexpected CF API update error: {e}", exc_info=True); break
            if is_retryable and attempt < MAX_CF_UPDATE_RETRIES:
                wait_time = CF_UPDATE_RETRY_DELAY * (CF_UPDATE_BACKOFF_FACTOR ** attempt); wait_time *= (1 + random.uniform(-0.2, 0.2)); wait_time = max(1, wait_time)
                if status_code == 429 and e.response is not None: retry_after = e.response.headers.get("Retry-After"); # ... (handle retry_after) ...
                logging.info(f"Retrying CF update in {wait_time:.1f}s...");
                if stop_event.wait(wait_time): logging.warning("Shutdown during CF update retry."); return False
            else: logging.error(f"CF API update failed, won't retry."); break
        logging.error(f"Failed CF update after {MAX_CF_UPDATE_RETRIES + 1} attempts."); error_message = f"Failed update tunnel config: {last_exception}"; cloudflared_agent_state["last_action_status"] = f"Error: {error_message}"; tunnel_state["error"] = error_message; return False
    else: return True

# --- process_container_start ---
# UPDATED: Add type='docker'
def process_container_start(container):
    if not container: return
    container_id = None
    try:
        container_id = container.id
        try: container.reload()
        except NotFound: logging.warning(f"Container {container_id[:12]} gone on start."); return
        labels = container.labels; container_name = container.name
        enabled_label = f"{LABEL_PREFIX}.enable"; hostname_label = f"{LABEL_PREFIX}.hostname"
        service_label = f"{LABEL_PREFIX}.service"; zone_name_label = f"{LABEL_PREFIX}.zonename"
        is_enabled = labels.get(enabled_label, "false").lower() in ["true", "1", "t", "yes"]
        hostname = labels.get(hostname_label); service = labels.get(service_label); zone_name = labels.get(zone_name_label)
        if not is_enabled: logging.debug(f"Ignore start {container_name}: not enabled."); return
        if not hostname or not service: logging.warning(f"Ignore start {container_name}: missing labels."); return
        # --- Validation (Hostname, Service) ---
        if not re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$", hostname): logging.warning(f"Ignore start {container_name}: invalid hostname."); return
        if not (re.match(r"^(https?|tcp|unix)://", service) or re.match(r"^[a-zA-Z0-9._-]+:\d+$", service)): logging.warning(f"Ignore start {container_name}: invalid service."); return

        # --- Determine Zone ID ---
        target_zone_id = None
        if zone_name: logging.info(f"Container {container_name} specified zone: '{zone_name}'."); target_zone_id = get_zone_id_from_name(zone_name)
        else: logging.debug(f"Container {container_name} uses default zone."); target_zone_id = CF_ZONE_ID
        if not target_zone_id: logging.error(f"Cannot manage DNS for {hostname}: No valid Zone ID."); return
        logging.info(f"Managing {hostname} ({container_name}) in Zone ID: {target_zone_id}")

        # --- Update State ---
        needs_cf_update = False; state_changed_locally = False
        with state_lock:
            existing_rule = managed_rules.get(hostname)
            rule_data = { # Prepare data for new or updated rule
                "service": service,
                "container_id": container_id,
                "status": "active",
                "delete_at": None,
                "zone_id": target_zone_id,
                "type": "docker" # <-- Set type
            }
            if existing_rule:
                if existing_rule.get("status") == "pending_deletion":
                    logging.info(f"Reactivating pending rule for {hostname}.")
                    managed_rules[hostname].update(rule_data) # Update existing entry
                    state_changed_locally = True; needs_cf_update = True
                elif existing_rule.get("status") == "active":
                    # Check for changes needing update
                    if existing_rule.get("service") != service or existing_rule.get("zone_id") != target_zone_id: needs_cf_update = True
                    if existing_rule.get("service") != service or existing_rule.get("container_id") != container_id or existing_rule.get("zone_id") != target_zone_id:
                        logging.info(f"Updating active rule details for {hostname}.")
                        managed_rules[hostname].update(rule_data)
                        state_changed_locally = True
            else:
                logging.info(f"Adding new docker rule for hostname: {hostname}")
                managed_rules[hostname] = rule_data # Add new entry
                state_changed_locally = True; needs_cf_update = True
            if state_changed_locally: save_state()

        # --- Update Cloudflare ---
        if needs_cf_update:
            logging.info(f"Triggering CF config update for {hostname}.")
            if update_cloudflare_config():
                logging.info(f"Tunnel update OK for {hostname}. Ensuring DNS in zone {target_zone_id}.")
                if tunnel_state.get("id"):
                    if not create_cloudflare_dns_record(target_zone_id, hostname, tunnel_state["id"]):
                        logging.error(f"CRITICAL: Tunnel updated but DNS create/verify FAILED for {hostname} in zone {target_zone_id}!")
                        cloudflared_agent_state["last_action_status"] = f"Error: DNS failed for {hostname} Z={target_zone_id}."
                else: logging.error("No Tunnel ID for DNS mgmt.")
            else: logging.error(f"Failed CF update for {hostname}. DNS not managed.")
        elif state_changed_locally: logging.debug(f"Local state updated for {hostname}, no CF change needed.")
    except Exception as e: logging.error(f"Error process start {container_id[:12] if container_id else 'Unknown'}: {e}", exc_info=True)

# --- schedule_container_stop ---
# No changes needed
def schedule_container_stop(container_id): # ... (previous implementation) ...
    if not container_id: return; logging.info(f"Processing stop event for {container_id[:12]}.")
    hostname_to_schedule = None; state_changed = False
    with state_lock:
        for hn, details in managed_rules.items():
            if details.get("container_id") == container_id and details.get("status") == "active" and details.get("type") == "docker": # Only schedule docker rules
                hostname_to_schedule = hn; break
        if hostname_to_schedule:
            logging.info(f"Docker rule {hostname_to_schedule} ({container_id[:12]}) stopped. Marking pending deletion.")
            rule = managed_rules[hostname_to_schedule]
            if rule.get("status") != "pending_deletion": rule["status"] = "pending_deletion"; rule["delete_at"] = datetime.now(timezone.utc) + timedelta(seconds=GRACE_PERIOD_SECONDS); logging.info(f"Rule {hostname_to_schedule} delete at {rule['delete_at'].isoformat()}"); state_changed = True
            else: logging.info(f"Rule {hostname_to_schedule} already pending.")
        else: logging.info(f"Stop event for {container_id[:12]}, no active docker rule found.")
        if state_changed: save_state()

# --- docker_event_listener ---
# No changes needed
def docker_event_listener(): # ... (previous implementation) ...
    if not docker_client: logging.error("No Docker client for listener."); return
    logging.info("Starting Docker event listener..."); error_count = 0; max_errors = 5
    while not stop_event.is_set() and error_count < max_errors:
        try:
            logging.info("Connecting event stream..."); events = docker_client.events(decode=True, since=int(time.time())); logging.info("Event stream connected."); error_count = 0
            for event in events:
                if stop_event.is_set(): logging.info("Stop event received, exiting listener."); break
                ev_type=event.get("Type"); action=event.get("Action"); actor=event.get("Actor",{}); cont_id=actor.get("ID")
                logging.debug(f"Event: T={ev_type} A={action} ID={cont_id[:12] if cont_id else 'N/A'}")
                if ev_type == "container" and cont_id:
                    if action == "start":
                        try: container = docker_client.containers.get(cont_id); process_container_start(container)
                        except Exception as e: logging.error(f"Error process start event {cont_id[:12]}: {e}", exc_info=True)
                    elif action in ["stop", "die", "destroy", "kill"]:
                         try: schedule_container_stop(cont_id)
                         except Exception as e: logging.error(f"Error process stop event {cont_id[:12]}: {e}", exc_info=True)
        except requests.exceptions.ConnectionError as e: error_count += 1; logging.error(f"Listener conn error: {e}. Reconnecting ({error_count}/{max_errors})...")
        except APIError as e: error_count += 1; logging.error(f"Listener API error: {e}. Reconnecting ({error_count}/{max_errors})...")
        except Exception as e: error_count += 1; logging.error(f"Unexpected listener error: {e}. Reconnecting ({error_count}/{max_errors})...", exc_info=True)
        if not stop_event.is_set(): stop_event.wait(min(30, 5 * error_count)) # Wait before retry if not stopping
    if error_count >= max_errors: logging.error("Listener stopping after multiple errors.")
    logging.info("Docker event listener stopped.")

# --- cleanup_expired_rules ---
# No changes needed
def cleanup_expired_rules(): # ... (previous implementation) ...
    logging.info("Starting cleanup task...");
    while not stop_event.is_set():
        next_check_time = time.time() + CLEANUP_INTERVAL_SECONDS
        try:
            logging.debug("Running cleanup check..."); rules_to_delete = {}; now_utc = datetime.now(timezone.utc); state_changed = False
            with state_lock:
                for hn, details in managed_rules.items():
                    if details.get("status") == "pending_deletion":
                        delete_at = details.get("delete_at"); is_expired = False
                        if isinstance(delete_at, datetime):
                             if delete_at.astimezone(timezone.utc) <= now_utc: is_expired = True
                        else: logging.warning(f"Rule {hn} pending invalid delete_at: {delete_at}. Expiring now."); is_expired = True
                        if is_expired: zone_id = details.get("zone_id", CF_ZONE_ID); # ... (rest is same) ...
                        if is_expired:
                            zone_id = details.get("zone_id", CF_ZONE_ID)
                            if not zone_id: logging.error(f"Cannot delete DNS for expired {hn}: No zone ID."); continue
                            rules_to_delete[hn] = zone_id; logging.info(f"Rule {hn} expired. Scheduling delete in zone {zone_id}.")
            if rules_to_delete:
                logging.info(f"Processing cleanup for: {list(rules_to_delete.keys())}")
                processed_hostnames = []; dns_ok = True
                for hn, zid in rules_to_delete.items():
                    if tunnel_state.get("id"):
                         if delete_cloudflare_dns_record(zid, hn, tunnel_state["id"]): processed_hostnames.append(hn)
                         else: logging.error(f"Failed DNS delete for {hn} in {zid}."); dns_ok = False; processed_hostnames.append(hn)
                    else: logging.error(f"Cannot delete DNS for {hn}: No tunnel ID."); dns_ok = False
                if processed_hostnames:
                    logging.info(f"Attempting CF update after DNS cleanup for: {processed_hostnames}")
                    if update_cloudflare_config():
                        logging.info(f"CF update OK. Removing rules from state: {processed_hostnames}")
                        with state_lock:
                            deleted_count = 0
                            for hn in processed_hostnames:
                                if hn in managed_rules and managed_rules[hn].get("status") == "pending_deletion": del managed_rules[hn]; deleted_count += 1; state_changed = True
                                else: logging.warning(f"Rule {hn} not found/pending during state removal.")
                            logging.info(f"Removed {deleted_count} rules from state.");
                            if state_changed: save_state()
                    else: logging.error("Failed CF update during cleanup. Will retry.")
            else: logging.debug("No expired rules found.")
        except Exception as e: logging.error(f"Error in cleanup loop: {e}", exc_info=True)
        stop_event.wait(max(0, next_check_time - time.time()))
    logging.info("Cleanup task stopped.")

# --- reconcile_state ---
# UPDATED: Handle 'type' field
def reconcile_state():
    if not docker_client: logging.warning("Reconcile: Docker client unavailable."); return
    if not tunnel_state.get("id"): logging.warning("Reconcile: Tunnel not initialized."); return
    logging.info("Starting state reconciliation..."); needs_cf_update = False; state_changed_locally = False
    try:
        # --- Get Docker State ---
        running_labeled_containers = {}
        try: containers = docker_client.containers.list(sparse=False); logging.debug(f"[Reconcile] Found {len(containers)} running.") # ... (rest of container listing logic) ...
        except (APIError, requests.exceptions.ConnectionError) as e: logging.error(f"[Reconcile] Docker error list: {e}. Abort."); return
        # --- (Populate running_labeled_containers as before) ---
        for c in containers:
            try:
                labels = c.labels; cid = c.id; cname = c.name
                enabled = labels.get(f"{LABEL_PREFIX}.enable", "false").lower() in ["true", "1", "t", "yes"]
                hn = labels.get(f"{LABEL_PREFIX}.hostname"); svc = labels.get(f"{LABEL_PREFIX}.service"); zn = labels.get(f"{LABEL_PREFIX}.zonename")
                if enabled and hn and svc:
                    # Basic validation
                    if not re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$", hn): continue
                    if not (re.match(r"^(https?|tcp|unix)://", svc) or re.match(r"^[a-zA-Z0-9._-]+:\d+$", svc)): continue
                    if hn in running_labeled_containers: logging.warning(f"[Reconcile] Dup hostname {hn} on {cname} & {running_labeled_containers[hn]['container_name']}.")
                    running_labeled_containers[hn] = {"service": svc, "container_id": cid, "container_name": cname, "zone_name": zn }
            except (NotFound, APIError) as e: logging.warning(f"[Reconcile] Error proc container {c.id[:12]}: {e}. Skip.")

        logging.info(f"[Reconcile] Found {len(running_labeled_containers)} valid labeled running containers.")

        # --- Compare ---
        with state_lock:
            logging.debug("[Reconcile] Acquired lock."); now_utc = datetime.now(timezone.utc)
            managed_hostnames = set(managed_rules.keys()); running_hostnames = set(running_labeled_containers.keys())
            hostnames_dns_check = []

            # 1. Check running containers
            for hostname, running_details in running_labeled_containers.items():
                target_zone_id = None; zone_name = running_details.get("zone_name")
                if zone_name: target_zone_id = get_zone_id_from_name(zone_name); # ... (handle lookup failure) ...
                else: target_zone_id = CF_ZONE_ID
                if not target_zone_id: logging.error(f"[Reconcile] Skip {hostname}: No valid Zone ID."); continue

                rule_data = { "service": running_details["service"], "container_id": running_details["container_id"], "status": "active", "delete_at": None, "zone_id": target_zone_id, "type": "docker" }

                if hostname in managed_rules:
                    rule = managed_rules[hostname]; zone_id_changed = rule.get("zone_id") != target_zone_id
                    if rule.get("status") == "pending_deletion":
                        logging.info(f"[Reconcile] Reactivating {hostname}."); rule.update(rule_data); state_changed_locally=True; needs_cf_update=True; hostnames_dns_check.append(hostname)
                    elif rule.get("status") == "active":
                        if rule.get("service") != running_details["service"] or rule.get("zone_id") != target_zone_id: needs_cf_update = True
                        if rule.get("service") != running_details["service"] or rule.get("container_id") != running_details["container_id"] or rule.get("zone_id") != target_zone_id:
                            logging.info(f"[Reconcile] Updating active rule {hostname}."); rule.update(rule_data); state_changed_locally = True
                        if zone_id_changed: hostnames_dns_check.append(hostname) # Check DNS in new zone
                    # If rule is manual, don't touch it based on container presence
                    elif rule.get("type") == "manual":
                         logging.debug(f"[Reconcile] Docker container running for manual rule {hostname}. Ignoring.")

                else: # New rule needed for running container
                    logging.info(f"[Reconcile] Adding new docker rule for {hostname}."); managed_rules[hostname] = rule_data; state_changed_locally=True; needs_cf_update=True; hostnames_dns_check.append(hostname)

            # 2. Check managed rules vs running
            for hostname in list(managed_hostnames):
                if hostname not in running_hostnames:
                     if hostname in managed_rules: # Check if still exists
                         rule = managed_rules[hostname]
                         # IMPORTANT: Only schedule deletion if it's a 'docker' type rule
                         if rule.get("status") == "active" and rule.get("type") == "docker":
                              logging.info(f"[Reconcile] Docker rule {hostname} active but container gone. Scheduling delete.")
                              rule["status"] = "pending_deletion"; rule["delete_at"] = now_utc + timedelta(seconds=GRACE_PERIOD_SECONDS); state_changed_locally = True
                         elif rule.get("status") == "active" and rule.get("type") == "manual":
                              logging.debug(f"[Reconcile] Manual rule {hostname} active and no container running. OK.")

            # 3. Compare local state vs CF state (no change needed here)
            # ... (previous comparison logic is fine) ...
            current_cf_config = get_current_cf_config()
            if current_cf_config is not None:
                cf_hostnames = {r.get("hostname") for r in current_cf_config.get("ingress", []) if r.get("hostname") and r.get("service") != "http_status:404"}
                active_managed = {hn for hn, d in managed_rules.items() if d.get("status") == "active"}
                if cf_hostnames != active_managed: logging.warning(f"[Reconcile] Mismatch: Managed={active_managed} vs CF={cf_hostnames}!"); needs_cf_update = True
            else: logging.error("[Reconcile] Failed CF config fetch for compare.")

            if state_changed_locally: logging.info("[Reconcile] Saving state changes."); save_state()
            logging.debug("[Reconcile] Releasing lock.")

        # --- Trigger Updates ---
        if needs_cf_update:
            logging.info("[Reconcile] Triggering CF tunnel update.");
            if update_cloudflare_config():
                 if hostnames_dns_check: # ... (DNS check logic is fine, uses rule["zone_id"]) ...
                      logging.info(f"[Reconcile] Checking DNS for: {hostnames_dns_check}")
                      for hn in hostnames_dns_check:
                           rule = None; with state_lock: rule = managed_rules.get(hn)
                           if rule and rule.get("zone_id") and tunnel_state.get("id"):
                                if not create_cloudflare_dns_record(rule["zone_id"], hn, tunnel_state["id"]): logging.error(f"[Reconcile] DNS check/create failed for {hn} in {rule['zone_id']}")
                           else: logging.error(f"[Reconcile] Cannot check/create DNS for {hn}: missing data.")
            else: logging.error("[Reconcile] Failed CF update. DNS checks skipped.")
        elif state_changed_locally: logging.info("[Reconcile] Local state only changes.")
        else: logging.info("[Reconcile] No changes needed.")
    except Exception as e: logging.error(f"Unexpected reconcile error: {e}", exc_info=True)
    finally: logging.info("Reconciliation complete.")


# --- get_cloudflared_container / update_cloudflared_container_status / ensure_docker_network_exists ---
# No changes needed
def get_cloudflared_container(): # ... (previous implementation) ...
    if not docker_client: logging.warning("Docker client unavailable."); return None
    try: return docker_client.containers.get(CLOUDFLARED_CONTAINER_NAME)
    except NotFound: logging.debug(f"Container '{CLOUDFLARED_CONTAINER_NAME}' not found."); return None
    except Exception as e: logging.error(f"Error getting container '{CLOUDFLARED_CONTAINER_NAME}': {e}"); return None

def update_cloudflared_container_status(): # ... (previous implementation) ...
    global docker_client
    if not docker_client:
        try: docker_client = docker.from_env(timeout=5); docker_client.ping(); logging.info("Reconnected to Docker.")
        except Exception as e: logging.error(f"Reconnect Docker failed: {e}"); cloudflared_agent_state["container_status"] = "docker_unavailable"; docker_client = None; return
    container = get_cloudflared_container()
    if container:
        try: container.reload(); new_status = container.status; # ... (rest of status update) ...
        except Exception as e: logging.warning(f"Error reloading agent status: {e}"); cloudflared_agent_state["container_status"] = "error" # Or not_found
    else: # ... (handle container not found) ...
        if cloudflared_agent_state.get("container_status") not in ["not_found", "docker_unavailable"]: logging.info("Agent container not found."); cloudflared_agent_state["container_status"] = "not_found"

def ensure_docker_network_exists(network_name): # ... (previous implementation) ...
     if not docker_client: logging.error("Docker client unavailable for network check."); return False
     try: docker_client.networks.get(network_name); logging.info(f"Network '{network_name}' exists."); return True
     except NotFound: logging.info(f"Network '{network_name}' creating..."); # ... (rest of creation logic) ...
     except Exception as e: logging.error(f"Error check/create network '{network_name}': {e}"); return False

# --- start_cloudflared_container / stop_cloudflared_container ---
# No changes needed
def start_cloudflared_container(): # ... (previous implementation, includes ensure_docker_network_exists) ...
     # ...
     if not ensure_docker_network_exists(CLOUDFLARED_NETWORK_NAME): return False
     # ...
def stop_cloudflared_container(): # ... (previous implementation) ...

# --- Flask App Setup ---
app = Flask(__name__)
app.secret_key = os.urandom(24) # Needed for flash messages


# --- get_display_token ---
# No changes needed
def get_display_token(token): # ... (previous implementation) ...

# --- status_page ---
# UPDATED: Pass grace period seconds
@app.route('/')
def status_page():
    update_cloudflared_container_status()
    with state_lock:
        rules_for_template = {}
        for hn, rule in managed_rules.items(): rules_for_template[hn] = rule.copy()
        template_tunnel_state = tunnel_state.copy(); template_agent_state = cloudflared_agent_state.copy()
        current_grace_period = GRACE_PERIOD_SECONDS # Read current value
    display_token = get_display_token(template_tunnel_state.get("token")); docker_available = docker_client is not None
    return render_template('status_page.html',
                            tunnel_state=template_tunnel_state, agent_state=template_agent_state,
                            display_token=display_token, cloudflared_container_name=CLOUDFLARED_CONTAINER_NAME,
                            docker_available=docker_available, rules=rules_for_template,
                            current_grace_period_seconds=current_grace_period) # Pass to template


# --- start_tunnel / stop_tunnel ---
# No changes needed
@app.route('/start', methods=['POST'])
def start_tunnel(): # ... (previous implementation) ...
@app.route('/stop', methods=['POST'])
def stop_tunnel(): # ... (previous implementation) ...


# --- force_delete_rule ---
# No changes needed (already uses stored zone_id)
@app.route('/force_delete/<hostname>', methods=['POST'])
def force_delete_rule(hostname): # ... (previous implementation) ...


# --- update_settings ---
# NEW Route: Handle grace period update
@app.route('/update_settings', methods=['POST'])
def update_settings():
    global GRACE_PERIOD_SECONDS
    logging.info("UI request: Update settings.")
    submitted_hours_str = request.form.get('grace_period_hours')
    action_status = None # Store feedback message

    try:
        if submitted_hours_str is None: raise ValueError("Missing form field")
        submitted_hours = float(submitted_hours_str) # Allow decimals like 0.5
        if submitted_hours < 0: raise ValueError("Grace period cannot be negative.")
        # Optional Max check: e.g., 7 days = 168 hours
        # if submitted_hours > 168: raise ValueError("Grace period exceeds maximum (168h).")

        new_grace_period_seconds = int(submitted_hours * 3600)
        if new_grace_period_seconds != GRACE_PERIOD_SECONDS:
            GRACE_PERIOD_SECONDS = new_grace_period_seconds
            logging.info(f"Grace period updated to: {GRACE_PERIOD_SECONDS} seconds ({submitted_hours} hours)")
            with state_lock: save_state() # Persist immediately
            action_status = f"Settings updated: Grace Period is now {submitted_hours} hours."
        else:
            action_status = f"Grace Period already set to {submitted_hours} hours. No change."

    except ValueError as e:
        logging.error(f"Invalid settings submission: {e} (Value: '{submitted_hours_str}')")
        action_status = f"Error: Invalid value for hours ({e})."
    except Exception as e:
        logging.error(f"Unexpected error updating settings: {e}", exc_info=True)
        action_status = f"Error updating settings: {e}."
    finally:
        # Use session flash messaging for better feedback (optional)
        # flash(action_status, 'info' if 'Error' not in action_status else 'error')
        # For now, use the existing last_action_status mechanism
        if action_status: cloudflared_agent_state["last_action_status"] = action_status

    return redirect(url_for('status_page'))

# --- add_manual_rule ---
# NEW Route: Handle manual rule creation
@app.route('/add_manual_rule', methods=['POST'])
def add_manual_rule():
    logging.info("UI request: Add manual rule.")
    hostname = request.form.get('manual_hostname')
    service = request.form.get('manual_service')
    zone_name = request.form.get('manual_zone_name') # Optional field
    action_status = None

    try:
        # --- Validation ---
        if not hostname or not service: raise ValueError("Hostname and Service URL are required.")
        # Hostname validation
        if not re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$", hostname):
             raise ValueError(f"Invalid hostname format '{hostname}'.")
        # Service validation
        if not (re.match(r"^(https?|tcp|udp|unix)://", service) or re.match(r"^[a-zA-Z0-9._-]+:\d+$", service) or re.match(r"^http_status:\d+$", service)):
             raise ValueError(f"Invalid service format '{service}'. Needs scheme or host:port or http_status:code.")
        # Check for duplicates
        with state_lock:
            if hostname in managed_rules:
                raise ValueError(f"Hostname '{hostname}' is already managed.")

        # --- Determine Zone ID ---
        target_zone_id = None
        if zone_name:
            logging.info(f"Manual rule specified zone name: '{zone_name}'. Looking up ID.")
            target_zone_id = get_zone_id_from_name(zone_name)
            if not target_zone_id: raise ValueError(f"Could not find Zone ID for name '{zone_name}'.")
        else:
            target_zone_id = CF_ZONE_ID # Use default
            if not target_zone_id: raise ValueError("Default CF_ZONE_ID is not set, and no zone name provided.")
        logging.info(f"Using Zone ID {target_zone_id} for manual rule {hostname}")

        # --- Add to State ---
        with state_lock:
            managed_rules[hostname] = {
                "service": service,
                "container_id": None, # No container for manual rules
                "status": "active",
                "delete_at": None,
                "zone_id": target_zone_id,
                "type": "manual" # <-- Set type
            }
            save_state()
        logging.info(f"Added manual rule for {hostname} to state.")
        state_changed_locally = True # Assume state change requires CF update

        # --- Update Cloudflare ---
        if state_changed_locally: # Always true when adding manually
            logging.info(f"Triggering Cloudflare config update for manual rule {hostname}.")
            if update_cloudflare_config():
                logging.info(f"Tunnel config update successful for {hostname}.")
                if tunnel_state.get("id"):
                    dns_record_id = create_cloudflare_dns_record(target_zone_id, hostname, tunnel_state["id"])
                    if dns_record_id:
                         logging.info(f"DNS record mgmt successful for {hostname} in zone {target_zone_id}.")
                         action_status = f"Successfully added manual rule for {hostname}."
                    else:
                         logging.error(f"CRITICAL: Added manual rule {hostname} but DNS create/verify FAILED in zone {target_zone_id}!")
                         action_status = f"Error: Added {hostname} but DNS failed in zone {target_zone_id}!"
                else:
                     logging.error(f"Cannot manage DNS for {hostname}: Tunnel ID missing.")
                     action_status = f"Error: Added {hostname} but Tunnel ID missing for DNS."
            else:
                logging.error(f"Failed to update Cloudflare tunnel config after adding manual rule {hostname}. State might be inconsistent.")
                # Attempt to roll back state change? More complex. Log clearly.
                action_status = f"Error: Added {hostname} locally, but FAILED pushing tunnel config update!"
                # Maybe remove from state again here if CF push fails?
                # with state_lock:
                #    if hostname in managed_rules and managed_rules[hostname].get("type") == "manual":
                #        del managed_rules[hostname]
                #        save_state()
                #        logging.info(f"Rolled back state addition for {hostname} due to CF update failure.")

    except ValueError as e:
        logging.error(f"Invalid manual rule submission: {e}")
        action_status = f"Error adding rule: {e}."
    except Exception as e:
        logging.error(f"Unexpected error adding manual rule: {e}", exc_info=True)
        action_status = f"Error adding rule: {e}."
    finally:
        if action_status: cloudflared_agent_state["last_action_status"] = action_status

    return redirect(url_for('status_page'))


# --- run_background_tasks ---
# No changes needed
def run_background_tasks(): # ... (previous implementation) ...

# --- Main Execution ---
if __name__ == '__main__':
    # ... (previous implementation, including commented network check if desired) ...
    logging.info("-" * 52); logging.info("--- DockFlare Tunnel Manager Starting ---"); logging.info("-" * 52)
    load_state(); logging.info("State loaded.")
    event_thread = None; cleanup_thread = None
    if not CF_API_TOKEN or not TUNNEL_NAME or not CF_ACCOUNT_ID: logging.error("FATAL: Missing required env vars."); sys.exit(1)
    if not docker_client: logging.error("Docker client unavailable. Limited functionality."); # ... (set state) ...
    else:
         logging.info("Docker client available.")
         # logging.info(f"Ensuring network '{CLOUDFLARED_NETWORK_NAME}' exists... (Check deferred)") # Keep commented if preferred
         logging.info("[DEBUG] >>> Calling initialize_tunnel()..."); initialize_tunnel()
         logging.info(f"Tunnel init complete. Status: {tunnel_state.get('status_message')}")
         logging.debug(f"Tunnel State: ID={tunnel_state.get('id')}, Token={bool(tunnel_state.get('token'))}, Err={tunnel_state.get('error')}")
         if tunnel_state.get("id") and tunnel_state.get("token"):
             logging.info("Tunnel ready. Reconciling state..."); reconcile_state()
             logging.info("Reconcile complete. Checking agent..."); update_cloudflared_container_status()
             if cloudflared_agent_state.get("container_status") != 'running': logging.info("Agent not running, starting..."); start_cloudflared_container()
             else: logging.info("Agent running.")
             event_thread, cleanup_thread = run_background_tasks()
         else: logging.warning("Tunnel not ready. Skipping reconcile, agent, background tasks."); # ... (set state) ...
    logging.info("Starting Flask web server..."); flask_thread = None
    try: from waitress import serve; flask_thread = threading.Thread(target=serve, args=(app,), kwargs={'host':'0.0.0.0','port':5000}, daemon=True, name="FlaskWaitressServer"); flask_thread.start(); logging.info("Waitress server started.")
    except ImportError: logging.warning("Waitress not found. Using Flask dev server."); app.run(host='0.0.0.0', port=5000)
    # --- Main Loop (keep alive, monitor threads) ---
    try:
        while True:
             all_threads_alive = True # ... (thread monitoring logic) ...
             if not all_threads_alive: logging.error("Critical thread died. Shutting down."); stop_event.set(); break
             if stop_event.is_set(): logging.info("Stop event detected."); break
             time.sleep(10)
    except KeyboardInterrupt: logging.info("KeyboardInterrupt received.")
    except Exception as server_err: logging.error(f"Web server failed: {server_err}", exc_info=True)
    finally: logging.info("Shutdown initiated..."); stop_event.set(); logging.info("Stop event set."); # ... (exit logic) ...