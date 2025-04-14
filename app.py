import os
import sys
import logging
import re
import json
import threading
import time
from datetime import datetime, timedelta, timezone

import docker # Docker SDK
from docker.errors import NotFound, APIError
from flask import Flask, jsonify, render_template_string, redirect, url_for, request
from dotenv import load_dotenv
import requests # Cloudflare API

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s') # Added thread name
load_dotenv()

# Cloudflare Config
CF_API_TOKEN = os.getenv('CF_API_TOKEN')
TUNNEL_NAME = os.getenv('TUNNEL_NAME')
CF_ACCOUNT_ID = os.getenv('CF_ACCOUNT_ID')
CF_API_BASE_URL = "https://api.cloudflare.com/client/v4"
CF_HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json",
}

# App Config
LABEL_PREFIX = os.getenv('LABEL_PREFIX', 'cloudflare.tunnel')
GRACE_PERIOD_SECONDS = int(os.getenv('GRACE_PERIOD_SECONDS', 28800)) # 8 hours default
CLEANUP_INTERVAL_SECONDS = int(os.getenv('CLEANUP_INTERVAL_SECONDS', 300)) # 5 mins default
STATE_FILE_PATH = os.getenv('STATE_FILE_PATH', '/app/state.json')

# Cloudflared Agent Config
CLOUDFLARED_CONTAINER_NAME = os.getenv('CLOUDFLARED_CONTAINER_NAME', f"cloudflared-agent-{TUNNEL_NAME}")
CLOUDFLARED_IMAGE = "cloudflare/cloudflared:latest"

# --- Environment Variable Checks ---
if not CF_API_TOKEN or not TUNNEL_NAME or not CF_ACCOUNT_ID:
    logging.error("FATAL: Missing required environment variables (CF_API_TOKEN, TUNNEL_NAME, CF_ACCOUNT_ID)")
    sys.exit(1)

# --- Docker Client ---
try:
    docker_client = docker.from_env()
    docker_client.ping()
    logging.info("Successfully connected to Docker daemon.")
except Exception as e:
    logging.error(f"FATAL: Failed to connect to Docker daemon: {e}")
    docker_client = None # Allow app to start but log error

# --- Global State & Locking ---
tunnel_state = { # Info about the tunnel itself
    "name": TUNNEL_NAME, "id": None, "token": None, "status_message": "Initializing...", "error": None
}
cloudflared_agent_state = { # Info about the running cloudflared container
    "container_status": "unknown", "last_action_status": None
}
managed_rules = {} # Our desired state: { hostname: { service, container_id, status, delete_at } }
state_lock = threading.Lock() # Lock for accessing managed_rules and updating CF config
stop_event = threading.Event() # To signal background threads to stop

# --- State Persistence ---
def load_state():
    """Loads managed_rules state from file."""
    global managed_rules
    if not os.path.exists(STATE_FILE_PATH):
        logging.info("State file not found, starting fresh.")
        managed_rules = {}
        return
    try:
        with open(STATE_FILE_PATH, 'r') as f:
            loaded_data = json.load(f)
            managed_rules = loaded_data
            logging.info(f"Loaded state for {len(managed_rules)} rules from {STATE_FILE_PATH}")
            for hostname, rule in managed_rules.items():
                 if rule.get("delete_at"):
                     try: rule["delete_at"] = datetime.fromisoformat(rule["delete_at"])
                     except (ValueError, TypeError): rule["delete_at"] = None
    except (json.JSONDecodeError, IOError, OSError) as e:
        logging.error(f"Error loading state from {STATE_FILE_PATH}: {e}. Starting fresh.", exc_info=True)
        managed_rules = {}

def save_state():
    """Saves managed_rules state to file."""
    with state_lock:
        try:
            serializable_state = {}
            for hostname, rule in managed_rules.items():
                rule_copy = rule.copy()
                if rule_copy.get("delete_at") and isinstance(rule_copy["delete_at"], datetime):
                    rule_copy["delete_at"] = rule_copy["delete_at"].isoformat()
                serializable_state[hostname] = rule_copy
            temp_file_path = STATE_FILE_PATH + ".tmp"
            with open(temp_file_path, 'w') as f:
                json.dump(serializable_state, f, indent=2)
            os.replace(temp_file_path, STATE_FILE_PATH)
            logging.debug(f"Saved state for {len(managed_rules)} rules to {STATE_FILE_PATH}")
        except (IOError, OSError) as e:
            logging.error(f"Error saving state to {STATE_FILE_PATH}: {e}", exc_info=True)


# --- Cloudflare API Helpers ---
def cf_api_request(method, endpoint, json_data=None, params=None):
    """Helper function to make Cloudflare API requests."""
    url = f"{CF_API_BASE_URL}{endpoint}"
    error_msg = None
    try:
        logging.info(f"API Request: {method} {url} Params: {params} Data: {json_data}")
        response = requests.request(method, url, headers=CF_HEADERS, json=json_data, params=params, timeout=30)
        response.raise_for_status()
        logging.info(f"API Response: {response.status_code}")
        if response.content: return response.json()
        else: return {"success": True}
    except requests.exceptions.RequestException as e:
        logging.error(f"API Request Failed: {method} {url}")
        error_msg = f"Request Exception: {e}"
        if e.response is not None:
            logging.error(f"Status Code: {e.response.status_code}")
            try: error_data = e.response.json()
            except ValueError: error_data = {"errors": [{"message": e.response.text[:100]}]}
            logging.error(f"Response Body: {error_data}")
            cf_errors = error_data.get('errors', [])
            error_msg = f"API Error: {cf_errors[0].get('message', 'Unknown error')}" if cf_errors else f"HTTP {e.response.status_code}"
        else: logging.error(f"Error details: {e}")
        if "cfd_tunnel" in endpoint and tunnel_state.get("id") is None: tunnel_state["error"] = error_msg
        raise requests.exceptions.RequestException(error_msg, response=e.response)

# --- Tunnel Initialization (API Based) ---
def find_tunnel_via_api(name):
    endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel"
    params = {"name": name, "is_deleted": "false"}
    try:
        response_data = cf_api_request("GET", endpoint, params=params)
        tunnels = response_data.get("result", [])
        if tunnels:
            tunnel = tunnels[0]; tunnel_id = tunnel.get("id")
            logging.info(f"Found existing tunnel '{name}' with ID: {tunnel_id} via API.")
            token = get_tunnel_token_via_api(tunnel_id)
            return tunnel_id, token
        else: logging.info(f"Tunnel '{name}' not found via API."); return None, None
    except Exception as e: logging.error(f"Error finding tunnel via API: {e}"); tunnel_state["error"] = f"Failed finding tunnel: {e}"; return None, None

def get_tunnel_token_via_api(tunnel_id):
    endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}/token"
    url = f"{CF_API_BASE_URL}{endpoint}"
    try:
        logging.info(f"API Request: GET {url} (for token)")
        response = requests.request("GET", url, headers=CF_HEADERS, timeout=30)
        response.raise_for_status(); token = response.text.strip()
        if not token or len(token) < 20: raise ValueError("Invalid token format")
        logging.info(f"Successfully retrieved token via API for tunnel {tunnel_id}")
        return token
    except requests.exceptions.RequestException as e:
        error_msg = f"API Error getting token: {e}";
        if e.response is not None: error_msg += f" Status: {e.response.status_code}"
        logging.error(error_msg, exc_info=True); tunnel_state["error"] = error_msg; raise

def create_tunnel_via_api(name):
    endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel"
    payload = {"name": name, "config_src": "cloudflare"}
    try:
        response_data = cf_api_request("POST", endpoint, json_data=payload)
        result = response_data.get("result", {}); tunnel_id = result.get("id"); token = result.get("token")
        if not tunnel_id or not token: raise ValueError("Missing ID or Token in API response")
        logging.info(f"Successfully created tunnel '{name}' with ID {tunnel_id} via API.")
        return tunnel_id, token
    except Exception as e: logging.error(f"Error creating tunnel via API: {e}"); tunnel_state["error"] = f"Failed creating tunnel: {e}"; return None, None

def initialize_tunnel():
    tunnel_state["status_message"] = f"Checking for tunnel '{TUNNEL_NAME}' via API..."; tunnel_state["error"] = None
    tunnel_id = None; token = None
    try:
        tunnel_id, token = find_tunnel_via_api(TUNNEL_NAME)
        if not tunnel_id and not tunnel_state.get("error"):
            tunnel_state["status_message"] = f"Tunnel '{TUNNEL_NAME}' not found. Creating via API..."
            tunnel_id, token = create_tunnel_via_api(TUNNEL_NAME)
        if tunnel_id and not token and not tunnel_state.get("error"): token = get_tunnel_token_via_api(tunnel_id)
        if tunnel_id and token:
            tunnel_state["id"] = tunnel_id; tunnel_state["token"] = token
            tunnel_state["status_message"] = "Tunnel setup complete (using API)."; tunnel_state["error"] = None
        elif not tunnel_state.get("error"):
             tunnel_state["status_message"] = "Tunnel initialization failed (API)."
             tunnel_state["error"] = "Failed to find/create tunnel or retrieve token."
    except Exception as e:
        logging.error(f"Error during tunnel initialization: {e}", exc_info=False)
        if not tunnel_state.get("error"): tunnel_state["error"] = f"Initialization failed: {e}"
        tunnel_state["status_message"] = "Tunnel initialization failed (API - see error details)."

# --- Cloudflare Tunnel Configuration Management ---
def get_current_cf_config():
    """Fetches the current tunnel configuration from Cloudflare."""
    if not tunnel_state.get("id"): logging.warning("Cannot get CF config, tunnel ID not available."); return None
    endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel/{tunnel_state['id']}/configurations"
    try:
        response_data = cf_api_request("GET", endpoint)
        if response_data and isinstance(response_data, dict) and response_data.get("success"):
            result_data = response_data.get("result")
            if isinstance(result_data, dict):
                 config_data = result_data.get("config")
                 if isinstance(config_data, dict):
                     logging.debug(f"Successfully fetched and parsed config: {config_data}")
                     return config_data # Return the actual config dict
                 else:
                      logging.info(f"Fetched config is null/empty (new tunnel?). Response: {response_data}")
                      return {} # Return empty dict if config is null/missing
            else:
                 logging.warning(f"API response has 'success:true' but no 'result' dictionary. Response: {response_data}")
                 return {} # Treat as empty/invalid config
        elif response_data:
             logging.warning(f"API response format unexpected or success flag not true. Response: {response_data}")
             return {} # Treat as empty/invalid config
        else: logging.error("cf_api_request returned None unexpectedly for GET config."); return None
    except Exception as e:
        logging.error(f"Exception caught in get_current_cf_config: {e}", exc_info=True)
        if not tunnel_state.get("error") or "API Error" not in tunnel_state["error"]:
             tunnel_state["error"] = f"Failed to get/parse tunnel config: {e}"
        return None

def update_cloudflare_config():
    """Pushes the desired state from managed_rules to Cloudflare Tunnel config."""
    if not tunnel_state.get("id"): logging.warning("Cannot update Cloudflare config, tunnel ID not available."); return False
    with state_lock:
        logging.info("Attempting to update Cloudflare tunnel configuration...")
        current_config = get_current_cf_config()
        if current_config is None: logging.error("Failed to fetch current config, aborting update."); return False

        new_ingress_rules = []; changed = False; catch_all_rule = {"service": "http_status:404"}
        current_hostnames_in_cf = {rule.get("hostname") for rule in current_config.get("ingress", []) if rule.get("hostname")}

        # Build new ingress list from active managed rules
        for hostname, rule_details in managed_rules.items():
            if rule_details["status"] == "active":
                desired_rule = {"hostname": hostname, "service": rule_details["service"]}
                found_in_cf = False
                for existing_rule in current_config.get("ingress", []):
                    if existing_rule.get("hostname") == hostname:
                        found_in_cf = True
                        if existing_rule.get("service") != rule_details["service"]: logging.info(f"Updating service for {hostname}."); changed = True
                        break
                if not found_in_cf: logging.info(f"Adding new hostname {hostname}."); changed = True
                new_ingress_rules.append(desired_rule)

        # Keep unmanaged rules (rules in CF but not in managed_rules)
        for existing_rule in current_config.get("ingress", []):
             if existing_rule.get("service") != catch_all_rule["service"]: # Exclude catch-all
                 if not existing_rule.get("hostname") or existing_rule.get("hostname") not in managed_rules:
                      logging.debug(f"Keeping unmanaged rule: {existing_rule}")
                      new_ingress_rules.append(existing_rule)

        # Detect if rules need removing (active in CF but not in active managed state)
        cf_hostnames_present_in_active_state = {r for r, d in managed_rules.items() if d['status'] == 'active'}
        if current_hostnames_in_cf - cf_hostnames_present_in_active_state:
             logging.info(f"Detected hostnames in CF to be removed: {current_hostnames_in_cf - cf_hostnames_present_in_active_state}")
             changed = True

        # Ensure catch-all is last
        new_ingress_rules = [rule for rule in new_ingress_rules if rule.get("service") != catch_all_rule["service"]]
        new_ingress_rules.append(catch_all_rule)

        # Final comparison
        current_cf_rules_no_catchall = [r for r in current_config.get("ingress", []) if r.get("service") != catch_all_rule["service"]]
        new_rules_no_catchall = new_ingress_rules[:-1]
        def rule_to_tuple(rule): return tuple(sorted(rule.items()))
        if not changed and set(map(rule_to_tuple, current_cf_rules_no_catchall)) != set(map(rule_to_tuple, new_rules_no_catchall)):
            logging.info("Detected difference in rule sets.")
            changed = True

        if not changed: logging.info("No changes detected in Cloudflare config. Skipping update."); return True

        logging.info("Pushing updated configuration to Cloudflare API...")
        endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel/{tunnel_state['id']}/configurations"
        payload = {"config": {"ingress": new_ingress_rules}}
        try:
            cf_api_request("PUT", endpoint, json_data=payload)
            logging.info("Successfully updated Cloudflare tunnel configuration.")
            return True
        except Exception as e:
            logging.error(f"Failed to update Cloudflare tunnel configuration: {e}")
            cloudflared_agent_state["last_action_status"] = f"Error updating CF config: {e}"
            return False

# --- Docker Event Handling ---
def process_container_start(container):
    """Processes a container start event."""
    if not container: return
    try:
        container.reload(); labels = container.labels; container_id = container.id; container_name = container.name
        enabled = labels.get(f"{LABEL_PREFIX}.enable", "false").lower() == "true"
        hostname = labels.get(f"{LABEL_PREFIX}.hostname")
        service = labels.get(f"{LABEL_PREFIX}.service")

        if not enabled: logging.debug(f"Ignoring start {container_name} ({container_id[:12]}): Not enabled."); return
        if not hostname or not service: logging.warning(f"Ignoring start {container_name} ({container_id[:12]}): Missing labels."); return
        if not re.match(r"^[a-zA-Z0-9.-]+$", hostname): logging.warning(f"Ignoring start {container_name} ({container_id[:12]}): Invalid hostname."); return
        if not service.startswith(("http://", "https://", "tcp://", "unix:")): logging.warning(f"Ignoring start {container_name} ({container_id[:12]}): Invalid service format."); return

        logging.info(f"Detected start for managed container: {container_name} ({container_id[:12]}) - Hostname: {hostname}, Service: {service}")
        needs_update = False; state_changed = False
        with state_lock:
            existing_rule = managed_rules.get(hostname)
            if existing_rule:
                if existing_rule["status"] == "pending_deletion":
                    logging.info(f"Cancelling pending deletion for {hostname}."); existing_rule["status"] = "active"; existing_rule["delete_at"] = None; needs_update = True; state_changed = True
                if existing_rule["service"] != service or existing_rule["container_id"] != container_id:
                    logging.info(f"Updating service/container for {hostname}."); existing_rule["service"] = service; existing_rule["container_id"] = container_id; state_changed = True
            else:
                logging.info(f"Adding new rule for {hostname}."); managed_rules[hostname] = {"service": service, "container_id": container_id, "status": "active", "delete_at": None}; needs_update = True; state_changed = True

        if needs_update:
             if update_cloudflare_config():
                 if state_changed: save_state() # Save state only if push succeeded and state changed
             else: logging.error(f"Failed update CF config for start {hostname}.")
        elif state_changed: save_state() # Save state if changed even if no API push needed immediately

    except NotFound: logging.warning(f"Container {container_id[:12]} not found during start processing.")
    except Exception as e: logging.error(f"Error processing container start: {e}", exc_info=True)

def schedule_container_stop(container_id):
    """Schedules a rule for deletion after grace period."""
    logging.info(f"Detected stop for container {container_id[:12]}. Scheduling rule deletion.")
    hostname_to_schedule = None; state_changed = False
    with state_lock:
        for hn, details in managed_rules.items():
            if details.get("container_id") == container_id and details.get("status") == "active":
                hostname_to_schedule = hn; break
        if hostname_to_schedule:
            logging.info(f"Marking hostname {hostname_to_schedule} for deletion.")
            rule = managed_rules[hostname_to_schedule]
            rule["status"] = "pending_deletion"; rule["delete_at"] = datetime.now(timezone.utc) + timedelta(seconds=GRACE_PERIOD_SECONDS); state_changed = True
        else: logging.info(f"Stop event for {container_id[:12]}, but no active rule found.")
    if state_changed: save_state()

def docker_event_listener():
    """Listens for Docker events in a background thread."""
    if not docker_client: logging.error("Docker client unavailable, listener not starting."); return
    logging.info("Starting Docker event listener...")
    try:
        events = docker_client.events(decode=True, since=int(time.time()))
        for event in events:
            if stop_event.is_set(): logging.info("Stop event received, exiting Docker event listener."); break
            ev_type = event.get("Type"); action = event.get("Action"); actor = event.get("Actor", {}); cont_id = actor.get("ID")
            logging.debug(f"Docker Event: Type={ev_type}, Action={action}, ActorID={cont_id[:12] if cont_id else 'N/A'}")
            if ev_type == "container" and cont_id:
                if action == "start":
                    try: container = docker_client.containers.get(cont_id); process_container_start(container)
                    except NotFound: logging.warning(f"Container {cont_id[:12]} not found after start event.")
                    except Exception as e: logging.error(f"Error getting container {cont_id[:12]} details: {e}", exc_info=True)
                elif action in ["stop", "die", "destroy"]: schedule_container_stop(cont_id) # Handle destroy too
    except Exception as e: logging.error(f"Error in Docker event listener: {e}", exc_info=True)
    finally: logging.info("Docker event listener stopped.")

# --- Cleanup Task ---
def cleanup_expired_rules():
    """Periodically checks for and removes expired rules."""
    logging.info("Starting cleanup task...")
    while not stop_event.is_set():
        try:
            logging.debug("Running cleanup check for expired rules...")
            hostnames_to_remove = []; now = datetime.now(timezone.utc); state_changed_in_cleanup = False
            with state_lock:
                for hostname, details in managed_rules.items():
                    if details.get("status") == "pending_deletion" and details.get("delete_at") and isinstance(details["delete_at"], datetime) and details["delete_at"] <= now:
                        logging.info(f"Rule for {hostname} expired. Scheduling removal."); hostnames_to_remove.append(hostname)
            if hostnames_to_remove:
                logging.info(f"Attempting removal of expired: {hostnames_to_remove}")
                if update_cloudflare_config(): # This removes them from CF implicitly
                    logging.info(f"CF config updated. Removing from local state: {hostnames_to_remove}")
                    with state_lock:
                        for hostname in hostnames_to_remove:
                            if hostname in managed_rules and managed_rules[hostname]["status"] == "pending_deletion":
                                del managed_rules[hostname]; state_changed_in_cleanup = True
                            else: logging.warning(f"Rule {hostname} no longer pending/present during cleanup removal.")
                    if state_changed_in_cleanup: save_state()
                else: logging.error("Failed CF update during cleanup. Will retry later.")
        except Exception as e: logging.error(f"Error in cleanup task: {e}", exc_info=True)
        stop_event.wait(CLEANUP_INTERVAL_SECONDS)
    logging.info("Cleanup task stopped.")

# --- Reconciliation ---
def reconcile_state():
    """Compares Docker state, local state, and CF config on startup."""
    if not docker_client: logging.warning("Docker client unavailable, skipping reconciliation."); return
    if not tunnel_state.get("id"): logging.warning("Tunnel not initialized, skipping reconciliation."); return
    logging.info("Starting state reconciliation..."); needs_cf_update = False; state_changed = False
    try:
        with state_lock:
            # 1. Get running containers
            running_labeled_containers = {}
            try:
                 containers = docker_client.containers.list()
                 for container in containers:
                     labels = container.labels; enabled = labels.get(f"{LABEL_PREFIX}.enable","f").lower()=="t"; hostname = labels.get(f"{LABEL_PREFIX}.hostname"); service = labels.get(f"{LABEL_PREFIX}.service")
                     if enabled and hostname and service: running_labeled_containers[hostname] = {"service": service, "container_id": container.id, "container_name": container.name}
                 logging.info(f"[Reconcile] Found {len(running_labeled_containers)} running labeled containers.")
            except APIError as e: logging.error(f"[Reconcile] Docker API error listing containers: {e}"); return

            # 2. Get CF config (only need hostnames here, full check in update_cloudflare_config)
            current_cf_config = get_current_cf_config()
            if current_cf_config is None: logging.error("[Reconcile] Cannot get CF config."); return
            cf_ingress_hostnames = {rule.get("hostname") for rule in current_cf_config.get("ingress", []) if rule.get("hostname")}
            logging.info(f"[Reconcile] Found {len(cf_ingress_hostnames)} hostnames in CF config.")

            # 3. Update state based on running containers
            now = datetime.now(timezone.utc); hostnames_processed = set()
            for hostname, running_details in running_labeled_containers.items():
                hostnames_processed.add(hostname)
                if hostname in managed_rules:
                    rule = managed_rules[hostname]
                    if rule["status"] == "pending_deletion": logging.info(f"[Reconcile] Reactivating {hostname}."); rule["status"] = "active"; rule["delete_at"] = None; needs_cf_update = True; state_changed = True
                    if rule["service"] != running_details["service"] or rule["container_id"] != running_details["container_id"]: logging.info(f"[Reconcile] Updating state for {hostname}."); rule["service"] = running_details["service"]; rule["container_id"] = running_details["container_id"]; state_changed = True # Need CF update if service changed
                else: logging.info(f"[Reconcile] Adding rule for running {hostname}."); managed_rules[hostname] = {"service": running_details["service"], "container_id": running_details["container_id"], "status": "active", "delete_at": None}; needs_cf_update = True; state_changed = True

            # 4. Update state for rules where container is NOT running
            for hostname, rule in list(managed_rules.items()):
                 if hostname not in hostnames_processed: hostnames_processed.add(hostname) # Mark as processed
                 if rule["status"] == "active" and hostname not in running_labeled_containers:
                      logging.info(f"[Reconcile] Scheduling deletion for {hostname} (container not running)."); rule["status"] = "pending_deletion"; rule["delete_at"] = now + timedelta(seconds=GRACE_PERIOD_SECONDS); state_changed = True; needs_cf_update = True # Needs CF update eventually
                 elif rule["status"] == "pending_deletion" and hostname in running_labeled_containers:
                      logging.info(f"[Reconcile] Container for {hostname} is running but state is pending delete. Reactivating."); rule["status"] = "active"; rule["delete_at"] = None; needs_cf_update = True; state_changed = True

            # 5. Trigger CF update if needed
            if needs_cf_update or state_changed: # Always run if state changed, even if needs_cf_update=false
                 logging.info(f"[Reconcile] State/CF sync needed (needs_cf_update={needs_cf_update}, state_changed={state_changed}). Triggering Cloudflare config update.")
                 if update_cloudflare_config():
                     if state_changed: save_state() # Save reconciled state only if push is successful
                 else: logging.error("[Reconcile] Failed Cloudflare config update.")
            else: logging.info("[Reconcile] No state changes detected.")

            logging.info("Reconciliation complete.")
    except Exception as e: logging.error(f"Error during state reconciliation: {e}", exc_info=True)

# --- Docker Container Management ---
def get_cloudflared_container():
    """Gets the cloudflared container object if it exists."""
    if not docker_client: logging.warning("Docker client not available."); return None
    try: return docker_client.containers.get(CLOUDFLARED_CONTAINER_NAME)
    except NotFound: return None
    except APIError as e: logging.error(f"Docker API error getting container: {e}"); cloudflared_agent_state["last_action_status"] = f"Error: Docker API error {e}"; return None

def update_cloudflared_container_status():
    """Updates the agent_state with the current container status."""
    if not docker_client: cloudflared_agent_state["container_status"] = "docker_unavailable"; return
    container = get_cloudflared_container()
    if container:
        try: container.reload(); cloudflared_agent_state["container_status"] = container.status
        except (NotFound, APIError) as e: logging.warning(f"Error reloading container status: {e}"); cloudflared_agent_state["container_status"] = "not_found"
    else: cloudflared_agent_state["container_status"] = "not_found"

def start_cloudflared_container():
    """Starts the cloudflared agent container using the token from tunnel_state."""
    logging.info("Entering start_cloudflared_container function.")
    cloudflared_agent_state["last_action_status"] = None
    success_flag = False
    try:
        if not docker_client: msg = "Docker client not available."; logging.error(msg); cloudflared_agent_state["last_action_status"] = f"Error: {msg}"; return False
        if not tunnel_state.get("token"): msg = "Tunnel token not available."; logging.error(msg); cloudflared_agent_state["last_action_status"] = f"Error: {msg}"; return False
        token = tunnel_state["token"]; container = get_cloudflared_container()
        logging.info(f"Checked for existing container: {'Found' if container else 'Not Found'}")
        if container:
            if container.status == 'running': msg = f"Container '{CLOUDFLARED_CONTAINER_NAME}' is already running."; logging.info(msg); cloudflared_agent_state["last_action_status"] = msg; success_flag = True; return True
            else: logging.info(f"Starting existing container '{CLOUDFLARED_CONTAINER_NAME}'..."); container.start(); msg = f"Successfully started container '{CLOUDFLARED_CONTAINER_NAME}'."; cloudflared_agent_state["last_action_status"] = msg; logging.info(msg); success_flag = True
        else:
            logging.info(f"Container '{CLOUDFLARED_CONTAINER_NAME}' not found. Creating and starting...")
            try: logging.info(f"Pulling image {CLOUDFLARED_IMAGE}..."); docker_client.images.pull(CLOUDFLARED_IMAGE)
            except APIError as img_err: logging.warning(f"Could not pull image {CLOUDFLARED_IMAGE}: {img_err}. Proceeding.")
            new_container = docker_client.containers.run(image=CLOUDFLARED_IMAGE, command=f"tunnel --no-autoupdate run --token {token}", name=CLOUDFLARED_CONTAINER_NAME, network_mode="host", restart_policy={"Name": "unless-stopped"}, detach=True, remove=False)
            msg = f"Successfully created and started container '{new_container.name}'."; cloudflared_agent_state["last_action_status"] = msg; logging.info(msg); success_flag = True
    except APIError as e: msg = f"Docker API error during start operation: {e}"; logging.error(msg, exc_info=True); cloudflared_agent_state["last_action_status"] = f"Error: {msg}"; success_flag = False
    except Exception as e: msg = f"Unexpected error starting container: {e}"; logging.error(msg, exc_info=True); cloudflared_agent_state["last_action_status"] = f"Error: {msg}"; success_flag = False
    finally:
        if docker_client: logging.debug("Updating container status after start attempt."); update_cloudflared_container_status()
        logging.info(f"Exiting start_cloudflared_container function (Success: {success_flag}).")
        return success_flag

def stop_cloudflared_container():
    """Stops the cloudflared agent container."""
    logging.info("Entering stop_cloudflared_container function.")
    cloudflared_agent_state["last_action_status"] = None; success_flag = False
    try:
        if not docker_client: msg = "Docker client not available."; logging.error(msg); cloudflared_agent_state["last_action_status"] = f"Error: {msg}"; return False
        container = get_cloudflared_container()
        if not container: msg = f"Container '{CLOUDFLARED_CONTAINER_NAME}' not found."; logging.warning(msg); cloudflared_agent_state["last_action_status"] = msg; success_flag = True; return True
        if container.status != 'running': msg = f"Container '{CLOUDFLARED_CONTAINER_NAME}' is not running (status: {container.status})."; logging.info(msg); cloudflared_agent_state["last_action_status"] = msg; success_flag = True; return True
        logging.info(f"Stopping container '{CLOUDFLARED_CONTAINER_NAME}'..."); container.stop(timeout=30); msg = f"Successfully stopped container '{CLOUDFLARED_CONTAINER_NAME}'."; cloudflared_agent_state["last_action_status"] = msg; logging.info(msg); success_flag = True
    except APIError as e: msg = f"Docker API error stopping container: {e}"; logging.error(msg, exc_info=True); cloudflared_agent_state["last_action_status"] = f"Error: {msg}"; success_flag = False
    except Exception as e: msg = f"Unexpected error stopping container: {e}"; logging.error(msg, exc_info=True); cloudflared_agent_state["last_action_status"] = f"Error: {msg}"; success_flag = False
    finally:
        if docker_client: logging.debug("Updating container status after stop attempt."); update_cloudflared_container_status()
        logging.info(f"Exiting stop_cloudflared_container function (Success: {success_flag}).")
        return success_flag

# --- Flask Web Server ---
app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def status_page():
    """Displays the current tunnel status and controls."""
    update_cloudflared_container_status()
    with state_lock: template_rules = json.loads(json.dumps(managed_rules, default=str))
    display_token = "Not available"
    if tunnel_state.get("token"): token = tunnel_state["token"]; display_token = f"{token[:5]}...{token[-5:]}" if len(token)>10 else "Token retrieved (short)"
    # (Using the same HTML template as before)
    html_template = """<!DOCTYPE html><html><head><title>Cloudflare Tunnel Manager</title><style>body{font-family:sans-serif;padding:20px;background-color:#f4f4f4;color:#333}h1,h2,h3{color:#555}.container{background-color:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1);margin-bottom:20px}table{width:100%;border-collapse:collapse;margin-top:15px}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background-color:#f2f2f2}td pre{margin:0;background-color:transparent;padding:0;white-space:pre-wrap;word-break:break-all}.status-box{padding:10px;border:1px solid #ccc;border-radius:5px;margin-top:10px;word-wrap:break-word}.error{background-color:#ffebeb;border-color:#ffc2c2;color:#a00}.success{background-color:#e6ffed;border-color:#c3e6cb;color:#155724}.info{background-color:#e7f3fe;border-color:#b8daff;color:#004085}.warning{background-color:#fff3cd;border-color:#ffeeba;color:#856404}.status-active{color:green}.status-pending{color:orange}.button{padding:10px 15px;border:none;border-radius:4px;color:#fff;cursor:pointer;font-size:1em;margin-right:10px}.start-button{background-color:#28a745}.stop-button{background-color:#dc3545}.button:disabled{background-color:#ccc;cursor:not-allowed;opacity:.6}form{display:inline-block}</style></head><body><h1>Cloudflare Tunnel Manager</h1><div class="container"><h2>Initialization Status</h2><div class="status-box {{'error' if tunnel_state.get('error') else ('success' if tunnel_state.get('token') else 'info')}}"><p><strong>Message:</strong> {{tunnel_state.status_message}}</p>{% if tunnel_state.get('error') %}<p><strong>Error Details:</strong> <pre>{{tunnel_state.error}}</pre></p>{% endif %}</div><h3>Tunnel Details</h3><p><strong>Desired Tunnel Name:</strong> <pre>{{tunnel_state.name}}</pre></p><p><strong>Tunnel ID:</strong> <pre>{{tunnel_state.id if tunnel_state.id else 'Not available'}}</pre></p><p><strong>Tunnel Token:</strong> <pre>{{display_token}}</pre></p></div><div class="container"><h2>Tunnel Agent Control (<pre>{{cloudflared_container_name}}</pre>)</h2><p><strong>Agent Container Status:</strong> <strong style="text-transform:capitalize" class="{{'success' if agent_state.container_status=='running' else ('error' if 'error' in agent_state.container_status or 'unavailable' in agent_state.container_status or agent_state.container_status=='dead' else ('warning' if agent_state.container_status=='exited' else 'info'))}}">{{agent_state.container_status.replace('_',' ')}}</strong></p>{% if agent_state.last_action_status %}<div class="status-box {{'error' if 'Error' in agent_state.last_action_status else 'info'}}"><strong>Last Action Result:</strong> {{agent_state.last_action_status}}</div>{% endif %}<form action="{{url_for('start_tunnel')}}" method="post" style="margin-right:10px"><button type="submit" class="button start-button" {{'disabled' if not tunnel_state.get('token') or agent_state.container_status=='running' or not docker_client}}>Start Tunnel Agent</button></form><form action="{{url_for('stop_tunnel')}}" method="post"><button type="submit" class="button stop-button" {{'disabled' if agent_state.container_status!='running' or not docker_client}}>Stop Tunnel Agent</button></form></div><div class="container"><h2>Managed Ingress Rules</h2>{% if rules %}<table><thead><tr><th>Hostname</th><th>Service Target</th><th>Status</th><th>Managing Container</th><th>Delete Scheduled At (UTC)</th></tr></thead><tbody>{% for hostname, details in rules.items() %}<tr><td><pre>{{hostname}}</pre></td><td><pre>{{details.service}}</pre></td><td><strong class="{{'status-active' if details.status=='active' else 'status-pending'}}">{{details.status}}</strong></td><td><pre>{{details.container_id[:12] if details.container_id else 'N/A'}}</pre></td><td>{{details.delete_at if details.status=='pending_deletion' else 'N/A'}}</td></tr>{% endfor %}</tbody></table>{% else %}<p>No ingress rules are currently being managed.</p>{% endif %}</div></body></html>"""
    return render_template_string(html_template, tunnel_state=tunnel_state, agent_state=cloudflared_agent_state, display_token=display_token, cloudflared_container_name=CLOUDFLARED_CONTAINER_NAME, docker_client=docker_client, rules=template_rules)

@app.route('/start', methods=['POST'])
def start_tunnel():
    start_cloudflared_container()
    return redirect(url_for('status_page'))

@app.route('/stop', methods=['POST'])
def stop_tunnel():
    stop_cloudflared_container()
    return redirect(url_for('status_page'))

# --- Main Execution ---
if __name__ == '__main__':
    logging.info("Application starting up...")
    load_state()
    logging.info("State loading complete.")
    try:
        initialize_tunnel()
        logging.info(f"Tunnel initialization complete. Status: {tunnel_state.get('status_message')}")
    except Exception as init_err: logging.error(f"Unhandled exception during initialize_tunnel: {init_err}", exc_info=True)

    logging.info(f"Checking tunnel state before agent start: ID={tunnel_state.get('id')}, Token Present={bool(tunnel_state.get('token'))}")
    if tunnel_state.get("id") and tunnel_state.get("token"):
         logging.info("Tunnel is initialized. Proceeding with reconciliation and agent start.")
         try: reconcile_state(); logging.info("Reconciliation complete.")
         except Exception as recon_err: logging.error(f"Error during initial reconciliation: {recon_err}", exc_info=True)
         logging.info("Attempting to automatically start tunnel agent...")
         agent_started_ok = False
         try: agent_started_ok = start_cloudflared_container()
         except Exception as start_err: logging.error(f"Unhandled exception calling start_cloudflared_container: {start_err}", exc_info=True); cloudflared_agent_state["last_action_status"] = f"Error: Unhandled exception during start ({start_err})"
         if agent_started_ok: logging.info("Call to start_cloudflared_container returned success.")
         else: logging.warning("Call to start_cloudflared_container returned failure.")
    else: logging.warning("Tunnel not fully initialized, skipping agent start and background tasks.")

    logging.info("Proceeding to background task and Flask setup.")
    if docker_client and tunnel_state.get("id"):
        logging.info("Starting background threads for Docker events and cleanup.")
        event_thread = threading.Thread(target=docker_event_listener, name="DockerEventListener", daemon=True)
        cleanup_thread = threading.Thread(target=cleanup_expired_rules, name="CleanupTask", daemon=True)
        event_thread.start(); cleanup_thread.start()
    else: logging.warning("Background tasks disabled (Docker client or Tunnel not ready).")

    logging.info("Starting Flask application server...")
    try: app.run(host='0.0.0.0', port=5000, use_reloader=False)
    except Exception as flask_err: logging.error(f"Flask server encountered an error: {flask_err}", exc_info=True)

    logging.info("Flask app stopping or encountered error, signalling background threads...")
    stop_event.set()
    logging.info("Exiting application.")