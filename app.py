# -*- coding: utf-8 -*-
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
from flask import Flask, jsonify, render_template, redirect, url_for, request, flash
from dotenv import load_dotenv
import requests

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s')
load_dotenv()

# Retry Config for CF PUT Tunnel Config
MAX_CF_UPDATE_RETRIES = int(os.getenv('MAX_CF_UPDATE_RETRIES', 3))
CF_UPDATE_RETRY_DELAY = int(os.getenv('CF_UPDATE_RETRY_DELAY', 2)) # Initial delay in seconds
CF_UPDATE_BACKOFF_FACTOR = float(os.getenv('CF_UPDATE_BACKOFF_FACTOR', 2.0)) # Multiplier for delay

# Cloudflare Config
CF_API_TOKEN = os.getenv('CF_API_TOKEN')
TUNNEL_NAME = os.getenv('TUNNEL_NAME')
CF_ACCOUNT_ID = os.getenv('CF_ACCOUNT_ID')
# CF_ZONE_ID is now the *default* zone ID if no label is specified
CF_ZONE_ID = os.getenv('CF_ZONE_ID') # Can be None
CF_API_BASE_URL = "https://api.cloudflare.com/client/v4"
CF_HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json",
}

# App Config
LABEL_PREFIX = os.getenv('LABEL_PREFIX', 'cloudflare.tunnel')
# Define specific label names using the prefix
LABEL_ENABLE = f"{LABEL_PREFIX}.enable"
LABEL_HOSTNAME = f"{LABEL_PREFIX}.hostname"
LABEL_SERVICE = f"{LABEL_PREFIX}.service"
LABEL_ZONE_NAME = f"{LABEL_PREFIX}.zonename" # <-- New Label Name

# Grace Period and Cleanup Intervals
DEFAULT_GRACE_PERIOD_SECONDS = 2 * 3600 # Default 2 hours
DEFAULT_CLEANUP_INTERVAL_SECONDS = 5 * 60 # Default 5 minutes
# Load from environment, falling back to defaults
GRACE_PERIOD_SECONDS = int(os.getenv('GRACE_PERIOD_SECONDS', DEFAULT_GRACE_PERIOD_SECONDS))
CLEANUP_INTERVAL_SECONDS = int(os.getenv('CLEANUP_INTERVAL_SECONDS', DEFAULT_CLEANUP_INTERVAL_SECONDS))

STATE_FILE_PATH = os.getenv('STATE_FILE_PATH', '/app/data/state.json')

# Cloudflared Agent Config
CLOUDFLARED_CONTAINER_NAME = os.getenv('CLOUDFLARED_CONTAINER_NAME', f"cloudflared-agent-{TUNNEL_NAME}")
CLOUDFLARED_IMAGE = os.getenv('CLOUDFLARED_IMAGE', "cloudflare/cloudflared:latest")
CLOUDFLARED_NETWORK_NAME = os.getenv('CLOUDFLARED_NETWORK_NAME', 'cloudflare-net')

# --- Environment Variable Checks ---
if not CF_API_TOKEN:
    logging.error("FATAL: Missing required environment variable: CF_API_TOKEN")
    sys.exit(1)
if not TUNNEL_NAME:
    logging.error("FATAL: Missing required environment variable: TUNNEL_NAME")
    sys.exit(1)
if not CF_ACCOUNT_ID:
    logging.error("FATAL: Missing required environment variable: CF_ACCOUNT_ID")
    sys.exit(1)
if not CF_ZONE_ID: # <--- UPDATED: Only warn if default is missing
    logging.warning(("CF_ZONE_ID environment variable is not set. "
                     "DNS management will ONLY work if containers specify the '%s' label."), LABEL_ZONE_NAME)

# --- Docker Client Setup ---
docker_client = None
try:
    # Increase timeout slightly for potentially slower systems/networks
    docker_client = docker.from_env(timeout=15)
    # Verify connection
    docker_client.ping()
    logging.info("Successfully connected to Docker daemon.")
except Exception as e:
    logging.error(f"FATAL: Failed to connect to Docker daemon: {e}")
    docker_client = None # Ensure it's None if connection failed

# --- Global State Variables ---
tunnel_state = {
    "name": TUNNEL_NAME,
    "id": None,
    "token": None,
    "status_message": "Initializing...",
    "error": None
}
cloudflared_agent_state = {
    "container_status": "unknown", # e.g., running, exited, not_found, docker_unavailable
    "last_action_status": None # User-friendly status from last operation
}
# managed_rules format:
# {
#   "hostname.example.com": {
#     "service": "http://container:80",
#     "container_id": "abc123...",
#     "status": "active" | "pending_deletion",
#     "delete_at": datetime | None, # UTC datetime when rule should be deleted if pending
#     "zone_id": "cf_zone_id_for_this_hostname" | None
#   }, ...
# }
managed_rules = {}
zone_id_cache = {} # Cache: { "zone.name": "zone_id", ... }
state_lock = threading.Lock() # Protects access to managed_rules, zone_id_cache, and state file IO
stop_event = threading.Event() # Signals background threads to stop

# --- State Persistence ---

def load_state():
    """Loads managed rules and settings from the state file."""
    global managed_rules
    global GRACE_PERIOD_SECONDS # Allow modification of the global variable

    # Start with the default grace period (from env var or hardcoded default)
    current_grace_period = GRACE_PERIOD_SECONDS
    logging.info(f"Initial GRACE_PERIOD_SECONDS (from env/default): {current_grace_period}")

    state_dir = os.path.dirname(STATE_FILE_PATH)
    if not os.path.exists(state_dir):
        try:
             os.makedirs(state_dir, exist_ok=True)
             logging.info(f"Created directory for state file: {state_dir}")
        except OSError as e:
             logging.error(f"FATAL: Could not create directory for state file {state_dir}: {e}. State persistence will fail.")
             managed_rules = {}
             return # Keep initial grace period

    if not os.path.exists(STATE_FILE_PATH):
        logging.info(f"State file '{STATE_FILE_PATH}' not found, starting fresh.")
        managed_rules = {}
        return # Keep initial grace period

    logging.info(f"Loading state from {STATE_FILE_PATH}...")
    try:
        with open(STATE_FILE_PATH, 'r') as f:
            loaded_data = json.load(f)

        # --- Load Grace Period Setting ---
        loaded_settings = loaded_data.get("settings", {})
        saved_grace_period = loaded_settings.get("grace_period_seconds")
        if saved_grace_period is not None:
            try:
                saved_grace_period_int = int(saved_grace_period)
                if saved_grace_period_int >= 0:
                    # Use the value from the state file if valid
                    GRACE_PERIOD_SECONDS = saved_grace_period_int
                    logging.info(f"Loaded and using GRACE_PERIOD_SECONDS from state: {GRACE_PERIOD_SECONDS}")
                else:
                    logging.warning(f"Invalid negative grace_period_seconds found in state: {saved_grace_period}. Using value from env/default: {current_grace_period}")
                    # Keep the initial value if loaded value is bad
                    GRACE_PERIOD_SECONDS = current_grace_period
            except (ValueError, TypeError):
                 logging.warning(f"Invalid non-integer grace_period_seconds found in state: {saved_grace_period}. Using value from env/default: {current_grace_period}")
                 GRACE_PERIOD_SECONDS = current_grace_period
        else:
             logging.info("No grace_period_seconds found in state settings. Using value from env/default.")
             # Keep the initial value if not found in state
             GRACE_PERIOD_SECONDS = current_grace_period

        # --- Load Rules ---
        loaded_rules = loaded_data.get("rules", {})
        parsed_rules = {}
        for hostname, rule in loaded_rules.items():
            rule_copy = rule.copy() # Work on a copy
            # Parse delete_at timestamp (handle multiple possible formats)
            delete_at_str = rule_copy.get("delete_at")
            if delete_at_str:
                try:
                    # Try ISO format with Z first
                    if delete_at_str.endswith('Z'):
                       dt = datetime.strptime(delete_at_str, '%Y-%m-%dT%H:%M:%SZ')
                       rule_copy["delete_at"] = dt.replace(tzinfo=timezone.utc)
                    # Try ISO format with offset
                    elif '+' in delete_at_str or (len(delete_at_str.split('-')) > 3 and '-' in delete_at_str[19:]):
                         rule_copy["delete_at"] = datetime.fromisoformat(delete_at_str).astimezone(timezone.utc)
                    # Add other formats if needed, e.g., space separator?
                    # else: raise ValueError("Unknown format")
                    else:
                         # Assume older space format? Be cautious or log warning
                         # dt = datetime.strptime(delete_at_str, '%Y-%m-%d %H:%M:%S.%f%z') # Example
                         logging.warning(f"Could not parse delete_at format '{delete_at_str}' for {hostname}. Removing timestamp.")
                         rule_copy["delete_at"] = None

                except (ValueError, TypeError) as dt_err:
                    logging.warning(f"Could not parse delete_at '{delete_at_str}' for {hostname}: {dt_err}. Removing timestamp.")
                    rule_copy["delete_at"] = None

            # Ensure zone_id exists, default to None if missing in old state files
            if "zone_id" not in rule_copy:
                rule_copy["zone_id"] = None
                logging.debug(f"Rule {hostname} loaded from state missing 'zone_id', defaulting to None.")

            parsed_rules[hostname] = rule_copy # Add parsed rule
        managed_rules = parsed_rules # Assign parsed rules

        logging.info(f"Successfully loaded state for {len(managed_rules)} rules from {STATE_FILE_PATH}")

    except (json.JSONDecodeError, IOError, OSError) as e:
        logging.error(f"Error loading state from {STATE_FILE_PATH}: {e}. Starting fresh.", exc_info=True)
        managed_rules = {}
        # Revert grace period to initial default on load error
        GRACE_PERIOD_SECONDS = current_grace_period
    except Exception as e:
         logging.error(f"Unexpected error during state load: {e}", exc_info=True)
         managed_rules = {}
         GRACE_PERIOD_SECONDS = current_grace_period


def save_state():
    """Saves the current managed rules and settings to the state file."""
    state_to_save = {
        "settings": {
            # Save current global value, which might have been updated via UI
            "grace_period_seconds": GRACE_PERIOD_SECONDS
        },
        "rules": {}
    }

    # Perform serialization outside the lock to minimize lock holding time
    # Create a deep copy of rules for serialization
    with state_lock:
        rules_snapshot = json.loads(json.dumps(managed_rules, default=str)) # Basic deep copy

    serialized_rules = {}
    for hostname, rule in rules_snapshot.items():
        rule_copy = rule.copy() # Work with the copied rule dict
        # Serialize datetime to ISO 8601 format with 'Z' for UTC
        if rule_copy.get("delete_at") and isinstance(rule_copy["delete_at"], str):
             # If it's already a string from the deep copy, try parsing and reformatting for consistency
             try:
                  dt = datetime.fromisoformat(rule_copy["delete_at"].replace('Z', '+00:00'))
                  rule_copy["delete_at"] = dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
             except ValueError:
                  logging.warning(f"Could not re-parse/format delete_at string '{rule_copy['delete_at']}' for {hostname} during save. Saving as is.")
                  # Keep the string as is if parsing fails
        elif rule_copy.get("delete_at"): # Should not happen if load_state works, but handle just in case
             logging.warning(f"Unexpected type for delete_at ({type(rule_copy.get('delete_at'))}) for {hostname} during save. Clearing.")
             rule_copy["delete_at"] = None

        # Ensure zone_id exists before saving, default to None
        if "zone_id" not in rule_copy:
            rule_copy["zone_id"] = None

        serialized_rules[hostname] = rule_copy

    state_to_save["rules"] = serialized_rules

    # Write to file (atomic replace)
    try:
        state_dir = os.path.dirname(STATE_FILE_PATH)
        # Ensure directory exists right before writing
        if not os.path.exists(state_dir):
            try:
                os.makedirs(state_dir, exist_ok=True)
                logging.info(f"Created directory {state_dir} just before saving state.")
            except OSError as e:
                logging.error(f"Could not create directory {state_dir} before saving state: {e}. Save failed.")
                return # Abort save

        temp_file_path = STATE_FILE_PATH + ".tmp" + str(random.randint(1000,9999)) # Add random suffix
        with open(temp_file_path, 'w') as f:
            json.dump(state_to_save, f, indent=2)

        # Ensure the temp file was written before replacing
        if os.path.exists(temp_file_path):
             os.replace(temp_file_path, STATE_FILE_PATH)
             logging.debug(f"Saved state ({len(serialized_rules)} rules, grace={GRACE_PERIOD_SECONDS}s) to {STATE_FILE_PATH}")
        else:
             logging.error(f"Temporary state file {temp_file_path} was not created. Save failed.")

    except (IOError, OSError) as e:
        logging.error(f"Error saving state to {STATE_FILE_PATH}: {e}", exc_info=True)
    except Exception as e:
         logging.error(f"Unexpected error during state save: {e}", exc_info=True)

# --- Cloudflare API Interaction ---

def cf_api_request(method, endpoint, json_data=None, params=None):
    """Makes a request to the Cloudflare API and handles basic error checking."""
    url = f"{CF_API_BASE_URL}{endpoint}"
    error_msg = None
    # Ensure headers are always fresh in case token changes (though it shouldn't here)
    request_headers = CF_HEADERS.copy()

    # Mask sensitive data in logs
    log_data = json.dumps(json_data) if json_data else None
    if log_data and 'config' in log_data: # Mask token in config if ever present
         log_data = log_data.replace(tunnel_state.get("token", "dummy_token_not_found"), "***TOKEN***")
    logging.debug(f"API Request: {method} {url} Params: {params} Data: {log_data}")

    try:
        response = requests.request(method, url, headers=request_headers, json=json_data, params=params, timeout=30) # 30 sec timeout
        response.raise_for_status() # Raises HTTPError for 4xx/5xx status codes
        logging.debug(f"API Response Status: {response.status_code}")

        # Handle empty responses (e.g., 204 No Content for DELETE)
        if response.status_code == 204 or not response.content:
            return {"success": True, "result": None} # Standardize successful empty response

        # Process JSON response
        try:
            response_data = response.json()
            # Log first 500 chars to avoid excessive logging
            logging.debug(f"API Response Body (first 500 chars): {str(response_data)[:500]}")

            if isinstance(response_data, dict) and 'success' in response_data:
                 if response_data['success']:
                      return response_data # Return the successful response dict
                 else:
                      # Cloudflare API reported failure (success=False)
                      cf_errors = response_data.get('errors', [])
                      if cf_errors and isinstance(cf_errors, list) and len(cf_errors) > 0 and isinstance(cf_errors[0], dict):
                           # Extract first error message
                           error_detail = cf_errors[0].get('message', 'Unknown API error')
                           error_code = cf_errors[0].get('code', 'N/A')
                           error_msg = f"API Error {error_code}: {error_detail}"
                           logging.error(f"API Request Failed ({method} {url}): {error_msg} - Full Errors: {cf_errors}")
                      else:
                           error_msg = f"API reported success=false but no error details provided. Response: {response_data}"
                           logging.error(f"API Request Failed ({method} {url}): {error_msg}")
                      # Raise an exception that can be caught by the caller
                      raise requests.exceptions.RequestException(error_msg, response=response)
            else:
                 # Valid JSON but not the expected format (missing 'success')
                 logging.warning(f"API response for {method} {url} was valid JSON but missing 'success' field. Status: {response.status_code}. Body: {str(response_data)[:200]}")
                 raise requests.exceptions.RequestException(f"Unexpected JSON response format from API. Status: {response.status_code}", response=response)

        except json.JSONDecodeError:
            logging.error(f"API response for {method} {url} was not valid JSON. Status: {response.status_code}. Body: {response.text[:200]}")
            raise requests.exceptions.RequestException(f"Invalid JSON response from API. Status: {response.status_code}", response=response)

    except requests.exceptions.HTTPError as e:
        # Handle 4xx/5xx errors specifically
        error_msg = f"HTTP Error: {e.response.status_code} {e.response.reason}"
        logging.error(f"API Request Failed: {method} {url} - {error_msg}")
        try:
            error_data = e.response.json()
            logging.error(f"Response Body: {error_data}")
            cf_errors = error_data.get('errors', [])
            if cf_errors and isinstance(cf_errors, list) and len(cf_errors) > 0 and isinstance(cf_errors[0], dict):
                error_detail = cf_errors[0].get('message', 'Unknown API error')
                error_code = cf_errors[0].get('code', 'N/A')
                error_msg = f"API Error {error_code}: {error_detail}" # Overwrite generic HTTP error
        except (ValueError, AttributeError, json.JSONDecodeError):
            error_msg += f" - Response Text: {e.response.text[:100]}" # Fallback if no JSON error details
        # Store critical errors in tunnel_state for UI visibility
        if "cfd_tunnel" in endpoint and "token" not in endpoint:
            tunnel_state["error"] = error_msg
        raise requests.exceptions.RequestException(error_msg, response=e.response) # Re-raise standard exception

    except requests.exceptions.RequestException as e:
        # Handle other request errors (timeout, connection error, etc.)
        if error_msg is None: # If not already set by specific handling above
             error_msg = f"Request Exception: {e}"
             logging.error(f"API Request Failed: {method} {url} - {error_msg}", exc_info=True) # Log traceback for these
        # Store critical errors in tunnel_state
        if "cfd_tunnel" in endpoint and "token" not in endpoint:
            tunnel_state["error"] = error_msg
        raise # Re-raise the original exception


def get_zone_id_from_name(zone_name):
    """
    Retrieves the Zone ID for a given zone name using the Cloudflare API.
    Caches the result to minimize API calls.
    Returns the Zone ID (str) or None if not found or an error occurs.
    Requires API Token with Zone:Zone:Read permissions.
    """
    global zone_id_cache
    if not zone_name:
        logging.warning("get_zone_id_from_name called with empty zone_name.")
        return None

    # Check cache first (thread-safe access needs lock)
    with state_lock:
        cached_id = zone_id_cache.get(zone_name)
    if cached_id:
        logging.debug(f"Zone ID for '{zone_name}' found in cache: {cached_id}")
        return cached_id

    logging.info(f"Zone ID for '{zone_name}' not in cache. Querying Cloudflare API...")
    endpoint = "/zones"
    # Match by name, ensure it's active, limit results per page (though usually 1)
    params = {"name": zone_name, "status": "active", "per_page": 5}

    try:
        response_data = cf_api_request("GET", endpoint, params=params)
        results = response_data.get("result", [])

        if results and isinstance(results, list):
             # Find the exact match among the results (API might return subdomains sometimes)
             exact_match = next((zone for zone in results if zone.get("name") == zone_name), None)
             if exact_match:
                 zone_id = exact_match.get("id")
                 if zone_id:
                     logging.info(f"Found Zone ID for '{zone_name}': {zone_id}")
                     # Store in cache (thread-safe)
                     with state_lock:
                         zone_id_cache[zone_name] = zone_id
                     return zone_id
                 else:
                     # Should not happen if API behaves, but check just in case
                     logging.error(f"API returned matching zone '{zone_name}' but without an ID: {exact_match}")
                     return None
             else:
                 # No exact match found (e.g., API returned results, but none had the exact name)
                 logging.warning(f"No *exact* active zone found matching name '{zone_name}' via API (found {len(results)} potential matches in response). Check spelling and zone status in Cloudflare.")
                 return None
        else:
            # No active zone with that name found
            logging.warning(f"No active zone found matching name '{zone_name}' via API.")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"API error looking up zone '{zone_name}': {e}")
        # Avoid caching failures permanently, maybe add temporary negative caching if needed
        return None
    except Exception as e:
        logging.error(f"Unexpected error looking up zone '{zone_name}': {e}", exc_info=True)
        return None

# --- Tunnel Management ---

def find_tunnel_via_api(name):
    """Finds a tunnel by name via API and returns its ID and Token."""
    logging.debug(f"Attempting to find tunnel '{name}' via API...")
    endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel"
    # Search by name, exclude deleted tunnels
    params = {"name": name, "is_deleted": "false", "per_page": 1}
    try:
        response_data = cf_api_request("GET", endpoint, params=params)
        tunnels = response_data.get("result", [])
        if tunnels and isinstance(tunnels, list):
            # API should return the exact match first if name param is used
            tunnel = tunnels[0]
            tunnel_id = tunnel.get("id")
            if tunnel_id:
                logging.info(f"Found existing tunnel '{name}' with ID: {tunnel_id} via API.")
                # Retrieve the token separately
                token = get_tunnel_token_via_api(tunnel_id)
                if token:
                    return tunnel_id, token
                else:
                    # Found tunnel ID but couldn't get token
                    logging.error(f"Found tunnel '{name}' (ID: {tunnel_id}) but failed to retrieve its token.")
                    tunnel_state["error"] = f"Failed to get token for existing tunnel {tunnel_id}"
                    return tunnel_id, None # Return ID even if token fetch failed initially
            else:
                 logging.warning(f"API returned a tunnel entry for '{name}' but it has no ID: {tunnel}")
                 return None, None
        else:
            logging.info(f"Tunnel '{name}' not found via API.")
            return None, None
    except requests.exceptions.RequestException as e:
        logging.error(f"API error finding tunnel '{name}': {e}")
        tunnel_state["error"] = f"API error finding tunnel: {e}"
        return None, None
    except Exception as e:
        logging.error(f"Unexpected error finding tunnel '{name}': {e}", exc_info=True)
        tunnel_state["error"] = f"Unexpected error finding tunnel: {e}"
        return None, None


def get_tunnel_token_via_api(tunnel_id):
    """Retrieves the runtime token for a given tunnel ID via API."""
    logging.debug(f"Retrieving token for tunnel ID '{tunnel_id}' via API...")
    endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}/token"
    url = f"{CF_API_BASE_URL}{endpoint}" # Construct URL manually for raw token response
    try:
        # Use requests directly as cf_api_request expects JSON response
        request_headers = {"Authorization": f"Bearer {CF_API_TOKEN}"}
        logging.debug(f"API Request: GET {url} (for token)")
        response = requests.request("GET", url, headers=request_headers, timeout=30)
        response.raise_for_status() # Check for HTTP errors

        token = response.text.strip() # Token is the raw response body

        # Basic validation of the token format/length
        if not token or len(token) < 50: # Adjust length check as needed
            logging.error(f"Retrieved token for tunnel {tunnel_id} appears invalid or unexpectedly short.")
            raise ValueError("Invalid token format received from API")

        logging.info(f"Successfully retrieved token via API for tunnel {tunnel_id}")
        return token
    except requests.exceptions.RequestException as e:
        error_msg = f"API Error getting token for tunnel {tunnel_id}: {e}"
        if e.response is not None:
             error_msg += f" Status: {e.response.status_code} Body: {e.response.text[:100]}"
        logging.error(error_msg)
        # Don't set tunnel_state error here directly, let find/create handle overall status
        raise # Re-raise so the caller knows token retrieval failed
    except Exception as e:
         logging.error(f"Unexpected error getting tunnel token for {tunnel_id}: {e}", exc_info=True)
         raise # Re-raise


def create_tunnel_via_api(name):
    """Creates a new tunnel via API and returns its ID and Token."""
    logging.info(f"Tunnel '{name}' not found. Attempting to create via API...")
    endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel"
    # 'config_src' determines where config is managed (API vs cloudflared file)
    payload = {"name": name, "config_src": "cloudflare"}
    try:
        response_data = cf_api_request("POST", endpoint, json_data=payload)
        result = response_data.get("result", {})
        tunnel_id = result.get("id")
        token = result.get("token") # Token is included in creation response

        if not tunnel_id or not token:
            logging.error(f"API response for tunnel creation missing ID or Token: {result}")
            raise ValueError("Missing ID or Token in tunnel creation API response")

        logging.info(f"Successfully created tunnel '{name}' with ID {tunnel_id} via API.")
        return tunnel_id, token
    except requests.exceptions.RequestException as e:
        logging.error(f"API error creating tunnel '{name}': {e}")
        tunnel_state["error"] = f"API error creating tunnel: {e}"
        return None, None
    except Exception as e:
        logging.error(f"Unexpected error creating tunnel '{name}': {e}", exc_info=True)
        tunnel_state["error"] = f"Unexpected error creating tunnel: {e}"
        return None, None


def initialize_tunnel():
    """Checks for existing tunnel, creates if necessary, and stores ID and Token."""
    logging.info(f"Initializing Cloudflare Tunnel '{TUNNEL_NAME}'...")
    tunnel_state["status_message"] = f"Checking for tunnel '{TUNNEL_NAME}'..."
    tunnel_state["error"] = None # Clear previous errors
    tunnel_id = None
    token = None

    try:
        tunnel_id, token = find_tunnel_via_api(TUNNEL_NAME)

        if not tunnel_id and not tunnel_state.get("error"):
            # If not found and no API error occurred during find, try creating
            tunnel_state["status_message"] = f"Tunnel '{TUNNEL_NAME}' not found. Creating..."
            tunnel_id, token = create_tunnel_via_api(TUNNEL_NAME)

        # Final check on results
        if tunnel_id and token:
            tunnel_state["id"] = tunnel_id
            tunnel_state["token"] = token
            tunnel_state["status_message"] = "Tunnel setup complete (via API)."
            tunnel_state["error"] = None # Clear any transient errors if we succeeded
            logging.info(f"Tunnel '{TUNNEL_NAME}' initialized successfully. ID: {tunnel_id}, Token retrieved.")
        elif tunnel_id and not token:
             # Found/Created tunnel but failed to get token (should have been caught earlier)
             tunnel_state["id"] = tunnel_id
             tunnel_state["token"] = None
             tunnel_state["status_message"] = "Tunnel found/created, but token retrieval failed."
             if not tunnel_state.get("error"): # Set error if not already set
                 tunnel_state["error"] = "Failed to retrieve token for the tunnel."
             logging.error(f"Tunnel initialization failed for '{TUNNEL_NAME}': Could not get Token for ID {tunnel_id}.")
        else:
            # Failed to find or create, or an API error occurred
            tunnel_state["id"] = None
            tunnel_state["token"] = None
            tunnel_state["status_message"] = "Tunnel initialization failed."
            if not tunnel_state.get("error"): # Set a generic error if none was set by API calls
                 tunnel_state["error"] = "Failed to find or create tunnel. Check logs and Cloudflare API Token permissions."
            logging.error(f"Tunnel initialization failed for '{TUNNEL_NAME}'. Error: {tunnel_state['error']}")

    except Exception as e:
        # Catch any unexpected errors during the initialization process
        logging.error(f"Unhandled exception during tunnel initialization: {e}", exc_info=True)
        if not tunnel_state.get("error"): tunnel_state["error"] = f"Initialization failed unexpectedly: {e}"
        tunnel_state["status_message"] = "Tunnel initialization failed (unexpected error)."

    logging.debug(f"Tunnel State after init: ID={tunnel_state.get('id')}, Token Present={bool(tunnel_state.get('token'))}, Error={tunnel_state.get('error')}")


def get_current_cf_config():
    """Fetches the current configuration for the managed tunnel from Cloudflare."""
    if not tunnel_state.get("id"):
        logging.warning("Cannot get Cloudflare config, tunnel ID not available.")
        return None

    endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel/{tunnel_state['id']}/configurations"
    logging.debug(f"Fetching current tunnel configuration for ID {tunnel_state['id']}...")
    try:
        response_data = cf_api_request("GET", endpoint)
        # API returns {'success': True, 'result': {'config': {'ingress': [...]}}}
        # or {'success': True, 'result': {'config': None}} if no config set
        if response_data and response_data.get("success"):
            result_data = response_data.get("result")
            if isinstance(result_data, dict):
                 config_data = result_data.get("config")
                 # Return the config dict (can be None or {}) or an empty dict if missing/invalid
                 if isinstance(config_data, dict):
                      logging.debug(f"Successfully fetched tunnel config: {config_data}")
                      return config_data
                 elif config_data is None:
                      logging.debug("Fetched tunnel config is null (no rules set). Returning empty config.")
                      return {} # Treat null config as empty
                 else:
                      logging.warning(f"Fetched tunnel config has unexpected type for 'config': {type(config_data)}. Returning empty config.")
                      return {}
            elif result_data is None: # Should not happen based on docs, but handle
                 logging.warning("Fetched tunnel config result is null. Returning empty config.")
                 return {}
            else:
                 logging.warning(f"Fetched tunnel config has unexpected 'result' format: {response_data}. Returning empty config.")
                 return {}
        else:
            # cf_api_request handles logging the error, just return None
            logging.error(f"API call to get tunnel config failed.")
            return None # Indicate failure to fetch
    except requests.exceptions.RequestException as e:
        logging.error(f"API error fetching tunnel config: {e}")
        if not tunnel_state.get("error"): tunnel_state["error"] = f"Failed get tunnel config: {e}"
        return None
    except Exception as e:
        logging.error(f"Unexpected error fetching tunnel config: {e}", exc_info=True)
        if not tunnel_state.get("error"): tunnel_state["error"] = f"Unexpected error getting tunnel config: {e}"
        return None


def update_cloudflare_config():
    """Updates the Cloudflare tunnel configuration with the desired ingress rules."""
    if not tunnel_state.get("id"):
        logging.warning("Cannot update Cloudflare config, tunnel ID is missing.")
        return False

    final_ingress_rules = None
    needs_api_update = False

    # --- Prepare desired state (within lock) ---
    with state_lock:
        logging.debug("Preparing desired Cloudflare tunnel ingress configuration...")
        desired_ingress_rules = []
        # Standard catch-all rule required by Cloudflare API when specifying ingress
        catch_all_rule = {"service": "http_status:404"}

        # Build rules from active state
        for hostname, rule_details in managed_rules.items():
            if rule_details.get("status") == "active":
                service = rule_details.get("service")
                if service:
                    desired_ingress_rules.append({"hostname": hostname, "service": service})
                else:
                    # This shouldn't happen with current logic, but check defensively
                    logging.warning(f"Rule for {hostname} is active but missing 'service' definition. Skipping.")

        # Sort rules by hostname for consistency and easier comparison
        desired_ingress_rules.sort(key=lambda x: x.get("hostname", ""))

        # --- Compare with current Cloudflare config ---
        logging.debug("Fetching current Cloudflare config for comparison...")
        current_config = get_current_cf_config()
        if current_config is None:
            logging.error("Failed to fetch current Cloudflare config. Aborting update.")
            return False # Cannot compare or update if fetch failed

        # Extract current rules from fetched config, excluding the catch-all
        current_cf_ingress = [
            r for r in current_config.get("ingress", [])
            if r.get("hostname") and r.get("service") != catch_all_rule["service"]
        ]

        # --- Normalize rules for comparison ---
        # Convert rule dicts to sorted tuples of items to ensure order doesn't matter
        def rule_to_canonical(rule):
            # Only include relevant keys for comparison
            items = sorted([(k, v) for k, v in rule.items() if k in ["hostname", "service"]])
            return tuple(items)

        try:
             # Create sets of canonical rules for easy comparison
             current_cf_set = {rule_to_canonical(r) for r in current_cf_ingress}
             desired_set = {rule_to_canonical(r) for r in desired_ingress_rules}
        except Exception as e:
             # Should not happen with simple dicts, but catch just in case
             logging.error(f"Error creating canonical rule sets for comparison: {e}", exc_info=True)
             return False

        # --- Determine if update is needed ---
        if current_cf_set == desired_set:
            logging.info("No changes detected in Cloudflare tunnel ingress configuration. Skipping API update.")
            needs_api_update = False
        else:
            logging.info("Change detected. Desired ingress rules differ from current Cloudflare config.")
            logging.debug(f"Current Cloudflare Rules: {current_cf_set}")
            logging.debug(f"Desired Rules (State): {desired_set}")
            needs_api_update = True
            # Prepare the final list including the mandatory catch-all rule
            final_ingress_rules = desired_ingress_rules + [catch_all_rule]

    # --- Perform API Update (outside lock) ---
    if needs_api_update and final_ingress_rules is not None:
        endpoint = f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel/{tunnel_state['id']}/configurations"
        payload = {"config": {"ingress": final_ingress_rules}}
        last_exception = None
        update_successful = False

        for attempt in range(MAX_CF_UPDATE_RETRIES + 1):
            try:
                logging.info(f"Attempting Cloudflare config push (Attempt {attempt + 1}/{MAX_CF_UPDATE_RETRIES + 1})...")
                cf_api_request("PUT", endpoint, json_data=payload)
                logging.info("Successfully updated Cloudflare tunnel configuration via API.")
                # Update status message on success
                timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
                cloudflared_agent_state["last_action_status"] = f"CF config updated successfully at {timestamp}"
                # Clear previous API errors related to tunnel config if successful
                if tunnel_state.get("error") and ("Failed update tunnel config" in tunnel_state["error"] or "API Error" in tunnel_state["error"]):
                     logging.info(f"Clearing previous API error after successful update: {tunnel_state['error']}")
                     tunnel_state["error"] = None
                update_successful = True
                break # Exit retry loop on success

            except requests.exceptions.RequestException as e:
                last_exception = e
                status_code = e.response.status_code if e.response is not None else None
                logging.warning(f"Cloudflare API update attempt {attempt + 1} failed: {e} (Status: {status_code})")

                # Decide if retry is appropriate
                is_retryable_status = status_code in [429, 500, 502, 503, 504]
                is_retryable_exception = isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout))

                if (is_retryable_status or is_retryable_exception) and attempt < MAX_CF_UPDATE_RETRIES:
                    # Calculate delay with backoff and jitter
                    base_delay = CF_UPDATE_RETRY_DELAY * (CF_UPDATE_BACKOFF_FACTOR ** attempt)
                    wait_time = base_delay * (1 + random.uniform(-0.2, 0.2)) # Add jitter
                    wait_time = max(1, wait_time) # Minimum 1 second wait

                    # Check for Retry-After header (common for 429)
                    if status_code == 429 and e.response is not None:
                         retry_after_header = e.response.headers.get("Retry-After")
                         if retry_after_header:
                              try:
                                   # Header value is usually seconds
                                   retry_after_seconds = int(retry_after_header)
                                   wait_time = max(wait_time, retry_after_seconds)
                                   logging.info(f"Respecting Retry-After header: waiting {retry_after_seconds}s")
                              except ValueError:
                                   logging.warning(f"Could not parse Retry-After header value: {retry_after_header}")

                    logging.info(f"Retrying Cloudflare update in {wait_time:.1f} seconds...")
                    # Wait for the calculated time, but check stop_event periodically
                    if stop_event.wait(wait_time):
                         logging.warning("Shutdown signal received during Cloudflare update retry wait. Aborting update.")
                         cloudflared_agent_state["last_action_status"] = "Error: CF update aborted during retry (shutdown)."
                         tunnel_state["error"] = "Failed update: aborted retry during shutdown."
                         return False # Abort update process
                    continue # Go to next retry attempt
                else:
                    # Non-retryable error or max retries reached
                    logging.error(f"Cloudflare API update failed definitively after {attempt + 1} attempts. Won't retry.")
                    break # Exit retry loop

            except Exception as e:
                # Catch unexpected errors during the API call itself
                last_exception = e
                logging.error(f"Unexpected error during Cloudflare API update attempt {attempt + 1}: {e}", exc_info=True)
                break # Exit retry loop

        # After the loop (or break)
        if not update_successful:
            logging.error(f"Failed to update Cloudflare tunnel config after {MAX_CF_UPDATE_RETRIES + 1} attempts.")
            error_message = f"Failed update tunnel config: {last_exception}"
            cloudflared_agent_state["last_action_status"] = f"Error: {error_message}"
            # Persist the error in tunnel_state for UI
            if not tunnel_state.get("error"): # Don't overwrite more specific errors
                tunnel_state["error"] = error_message
            return False # Indicate failure
        else:
             return True # Indicate success

    elif needs_api_update and final_ingress_rules is None:
        # This case indicates an internal logic error
        logging.error("Internal error: Update needed but final ingress rules list is None. Aborting update.")
        return False
    else:
        # No update was needed
        return True # Success (no update required)

# --- DNS Management ---

def find_dns_record_id(zone_id, hostname, tunnel_id):
    """Finds the ID of a specific CNAME DNS record pointing to the tunnel."""
    if not zone_id or not hostname or not tunnel_id:
        logging.error(f"find_dns_record_id: Missing required arguments (Zone={zone_id}, Host={hostname}, Tunnel={tunnel_id}).")
        return None

    # Cloudflare automatically uses this CNAME target for tunnel DNS
    expected_content = f"{tunnel_id}.cfargotunnel.com"
    endpoint = f"/zones/{zone_id}/dns_records"
    params = {
        "type": "CNAME",
        "name": hostname,
        "content": expected_content,
        "match": "all", # Ensure all parameters match
        "per_page": 1 # We only expect one record
    }
    logging.debug(f"Searching DNS: Zone={zone_id}, Type=CNAME, Name={hostname}, Content={expected_content}")
    try:
        response_data = cf_api_request("GET", endpoint, params=params)
        results = response_data.get("result", [])
        if results and isinstance(results, list):
            # Should only be one result due to params and per_page=1
            record_id = results[0].get("id")
            if record_id:
                logging.debug(f"Found DNS record for {hostname} in zone {zone_id} with ID: {record_id}")
                return record_id
            else:
                logging.warning(f"DNS record search for {hostname} returned a result but it lacks an ID: {results[0]}")
                return None
        else:
            logging.debug(f"No matching DNS CNAME record found for {hostname} in zone {zone_id} pointing to tunnel {tunnel_id}.")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"API error finding DNS record for {hostname} in zone {zone_id}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error finding DNS record for {hostname} in zone {zone_id}: {e}", exc_info=True)
        return None


def create_cloudflare_dns_record(zone_id, hostname, tunnel_id):
    """Creates or verifies the CNAME DNS record for a hostname pointing to the tunnel."""
    if not zone_id or not hostname or not tunnel_id:
        logging.error(f"create_cloudflare_dns_record: Missing required arguments (Zone={zone_id}, Host={hostname}, Tunnel={tunnel_id}).")
        return None # Indicate failure

    # First, check if the correct record already exists
    existing_id = find_dns_record_id(zone_id, hostname, tunnel_id)
    if existing_id:
        logging.info(f"DNS CNAME record for {hostname} in zone {zone_id} pointing to tunnel {tunnel_id} already exists (ID: {existing_id}).")
        return existing_id # Return existing ID as success

    # If not found, create it
    record_name = hostname
    record_content = f"{tunnel_id}.cfargotunnel.com"
    endpoint = f"/zones/{zone_id}/dns_records"
    # Create as Proxied (Orange Cloud) CNAME with TTL=1 (Auto)
    payload = {
        "type": "CNAME",
        "name": record_name,
        "content": record_content,
        "ttl": 1, # 1 = Auto TTL
        "proxied": True
    }
    logging.info(f"Creating DNS CNAME in zone {zone_id}: Name={record_name}, Content={record_content}, Proxied=True")
    try:
        response_data = cf_api_request("POST", endpoint, json_data=payload)
        result = response_data.get("result", {})
        new_record_id = result.get("id")
        if new_record_id:
            logging.info(f"Successfully created DNS record for {hostname} in zone {zone_id}. New ID: {new_record_id}")
            return new_record_id # Return new ID as success
        else:
            # Should not happen if success=true, but check defensively
            logging.error(f"DNS record creation API call for {hostname} succeeded but response missing record ID: {result}")
            return None # Indicate failure
    except requests.exceptions.RequestException as e:
        # Check for specific error code indicating record already exists (e.g., 81057)
        # This can happen in race conditions or if find_dns_record_id failed temporarily
        is_duplicate_error = False
        if e.response is not None:
             try:
                 error_data = e.response.json()
                 cf_errors = error_data.get("errors", [])
                 if cf_errors and cf_errors[0].get("code") == 81057: # 81057: Record already exists.
                      is_duplicate_error = True
             except (json.JSONDecodeError, IndexError, TypeError, AttributeError):
                  pass # Ignore if response wasn't as expected

        if is_duplicate_error:
             logging.warning(f"DNS record creation for {hostname} failed because it already exists (Code 81057). Attempting to find it again.")
             # Retry finding the record ID
             time.sleep(1) # Brief pause before retry
             retry_id = find_dns_record_id(zone_id, hostname, tunnel_id)
             if retry_id:
                  logging.info(f"Found existing DNS record ID {retry_id} for {hostname} after creation conflict.")
                  return retry_id
             else:
                  logging.error(f"Failed to find DNS record for {hostname} even after creation conflict error.")
                  return None
        else:
             # Log other API errors
             logging.error(f"API error creating DNS record for {hostname} in zone {zone_id}: {e}")
             return None # Indicate failure
    except Exception as e:
        logging.error(f"Unexpected error creating DNS record for {hostname} in zone {zone_id}: {e}", exc_info=True)
        return None # Indicate failure


def delete_cloudflare_dns_record(zone_id, hostname, tunnel_id):
    """Deletes the specific CNAME DNS record pointing to the tunnel."""
    if not zone_id or not hostname or not tunnel_id:
        logging.error(f"delete_cloudflare_dns_record: Missing required arguments (Zone={zone_id}, Host={hostname}, Tunnel={tunnel_id}).")
        return False # Indicate failure

    # Find the record ID first
    dns_record_id = find_dns_record_id(zone_id, hostname, tunnel_id)
    if not dns_record_id:
        logging.warning(f"DNS record for {hostname} in zone {zone_id} pointing to tunnel {tunnel_id} not found. Assuming already deleted or never existed.")
        return True # Treat as success if record doesn't exist

    # If found, attempt deletion
    logging.info(f"Attempting to delete DNS record for {hostname} in zone {zone_id} (ID: {dns_record_id})")
    endpoint = f"/zones/{zone_id}/dns_records/{dns_record_id}"
    try:
        cf_api_request("DELETE", endpoint)
        logging.info(f"Successfully deleted DNS record for {hostname} (ID: {dns_record_id}).")
        return True # Indicate success
    except requests.exceptions.RequestException as e:
        # If the record was already deleted between find and delete (race condition),
        # Cloudflare returns 404. Treat 404 as success in this context.
        if e.response is not None and e.response.status_code == 404:
             logging.warning(f"DNS record {dns_record_id} for {hostname} not found during delete attempt (404). Treating as success (already deleted).")
             return True
        else:
            # Log other API errors
            logging.error(f"API error deleting DNS record {dns_record_id} for {hostname} in zone {zone_id}: {e}")
            return False # Indicate failure
    except Exception as e:
        logging.error(f"Unexpected error deleting DNS record {dns_record_id} for {hostname} in zone {zone_id}: {e}", exc_info=True)
        return False # Indicate failure


# --- Docker Event Handling and Rule Management ---

def process_container_start(container):
    """Processes a container start event to potentially add/update a managed rule."""
    if not container:
        logging.debug("process_container_start called with None container.")
        return
    container_id = None
    container_name = "Unknown"
    try:
        # Ensure we have fresh container info
        try:
             container.reload()
             container_id = container.id
             container_name = container.name
             labels = container.labels
        except NotFound:
             # Container might have stopped very quickly after starting
             logging.warning(f"Container {getattr(container, 'id', 'with unknown ID')[:12]} not found when processing start event (stopped quickly?).")
             return
        except APIError as e:
             logging.error(f"Docker API error reloading container {getattr(container, 'id', 'with unknown ID')[:12]} during start processing: {e}")
             return # Avoid processing potentially stale data

        # --- Extract Labels ---
        is_enabled = labels.get(LABEL_ENABLE, "false").lower() in ["true", "1", "t", "yes", "y"]
        hostname = labels.get(LABEL_HOSTNAME)
        service = labels.get(LABEL_SERVICE)
        zone_name = labels.get(LABEL_ZONE_NAME) # Read optional zone name label

        # --- Basic Validation ---
        if not is_enabled:
            logging.debug(f"Ignoring start: {container_name} ({container_id[:12]}): '{LABEL_ENABLE}' not true.")
            return
        if not hostname or not service:
            logging.warning(f"Ignoring start: {container_name} ({container_id[:12]}): Missing required label '{LABEL_HOSTNAME}' or '{LABEL_SERVICE}'.")
            return
        # Validate hostname format (simple check)
        if not re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$", hostname):
             logging.warning(f"Ignoring start: {container_name} ({container_id[:12]}): Invalid hostname format specified in label '{LABEL_HOSTNAME}': '{hostname}'.")
             return
        # Validate service format (allow scheme:// or host:port)
        if not (re.match(r"^(https?|tcp|unix)://.+", service) or re.match(r"^[a-zA-Z0-9._-]+:\d+$", service)):
             logging.warning(f"Ignoring start: {container_name} ({container_id[:12]}): Invalid service format specified in label '{LABEL_SERVICE}': '{service}'. Expected scheme://host:port or host:port.")
             return

        # --- Determine Target Zone ID ---
        target_zone_id = None
        zone_lookup_source = "N/A"
        if zone_name:
            zone_lookup_source = f"label '{LABEL_ZONE_NAME}'='{zone_name}'"
            logging.info(f"Container {container_name} specified zone name: '{zone_name}'. Looking up ID.")
            target_zone_id = get_zone_id_from_name(zone_name)
            if not target_zone_id:
                logging.error(f"Failed to find Zone ID for specified name '{zone_name}' (from container {container_name}). Cannot manage DNS for {hostname}. Skipping rule creation/update.")
                # Optionally provide feedback via last_action_status if needed, though it might be noisy
                # cloudflared_agent_state["last_action_status"] = f"Error: Invalid zone '{zone_name}' for {hostname}"
                return # Stop processing this container if specified zone lookup fails
        else:
            zone_lookup_source = f"default CF_ZONE_ID env var"
            logging.debug(f"Container {container_name} did not specify label '{LABEL_ZONE_NAME}'. Using default Zone ID from CF_ZONE_ID.")
            target_zone_id = CF_ZONE_ID # Use default from environment

        # Final check if a Zone ID was determined
        if not target_zone_id:
             logging.error(f"Cannot manage DNS for {hostname} (container {container_name}): No valid Zone ID found. Source checked: {zone_lookup_source}. Ensure the label is correct or the CF_ZONE_ID environment variable is set.")
             # cloudflared_agent_state["last_action_status"] = f"Error: No Zone ID for {hostname}." # Optional feedback
             return # Stop processing this container

        logging.info(f"Processing start event for {hostname} (from {container_name}) using Zone ID: {target_zone_id}")

        # --- Update Internal State (inside lock) ---
        needs_cf_update = False
        state_changed_locally = False
        with state_lock:
            existing_rule = managed_rules.get(hostname)

            if existing_rule:
                # Rule for this hostname already exists
                current_zone_id_in_state = existing_rule.get("zone_id")
                zone_id_changed = current_zone_id_in_state != target_zone_id

                if existing_rule.get("status") == "pending_deletion":
                    logging.info(f"[State] Rule for {hostname} was pending deletion. Reactivating.")
                    existing_rule["status"] = "active"
                    existing_rule["delete_at"] = None
                    existing_rule["service"] = service # Update service in case it changed
                    existing_rule["container_id"] = container_id # Update container ID
                    existing_rule["zone_id"] = target_zone_id # Update stored zone ID
                    state_changed_locally = True
                    needs_cf_update = True # Need to push change to CF config
                    if zone_id_changed: logging.info(f"[State] Zone ID for reactivated {hostname} updated from '{current_zone_id_in_state}' to '{target_zone_id}'.")
                    else: logging.debug(f"[State] Reactivated {hostname} using same Zone ID {target_zone_id}.")

                elif existing_rule.get("status") == "active":
                    # Rule already active, check for changes
                    service_changed = existing_rule.get("service") != service
                    container_changed = existing_rule.get("container_id") != container_id

                    if container_changed:
                        logging.info(f"[State] Updating container ID for active rule {hostname}: {existing_rule.get('container_id', 'N/A')[:12]} -> {container_id[:12]}.")
                        existing_rule["container_id"] = container_id
                        state_changed_locally = True # Local state change only

                    if service_changed:
                         logging.info(f"[State] Updating service for active rule {hostname}: '{existing_rule.get('service')}' -> '{service}'.")
                         existing_rule["service"] = service
                         state_changed_locally = True
                         needs_cf_update = True # Service change requires CF config update

                    if zone_id_changed:
                         # Important: Changing zone ID for an active rule.
                         # We update the state, but DNS in the *old* zone isn't automatically deleted here.
                         # Cleanup/reconciliation *might* catch it if the old container stops, but it's not guaranteed.
                         logging.warning(f"[State] Zone ID for active rule {hostname} changed ('{current_zone_id_in_state}' -> '{target_zone_id}'). Updating state. DNS record might be stale in old zone {current_zone_id_in_state}.")
                         existing_rule["zone_id"] = target_zone_id
                         state_changed_locally = True
                         # Needs CF update (implicitly true if service changed, explicitly needed if only zone changed?)
                         # Let's assume changing zone implicitly needs DNS update, which follows CF update.
                         # We don't trigger CF update *just* for zone change, but DNS check will happen after any *other* CF update.

                    # If nothing changed, just log debug message
                    if not service_changed and not container_changed and not zone_id_changed:
                         logging.debug(f"Container {container_name} started for already active and unchanged rule {hostname}.")

            else:
                # New rule for this hostname
                logging.info(f"[State] Adding new active rule for hostname: {hostname}")
                managed_rules[hostname] = {
                    "service": service,
                    "container_id": container_id,
                    "status": "active",
                    "delete_at": None,
                    "zone_id": target_zone_id # Store the determined Zone ID
                }
                state_changed_locally = True
                needs_cf_update = True # New rule requires CF config update

            # Save state file if any local changes occurred
            if state_changed_locally:
                logging.debug(f"Local state changed for {hostname}, saving state file...")
                save_state() # Save within lock

        # --- Update Cloudflare (outside lock) ---
        if needs_cf_update:
            logging.info(f"Triggering Cloudflare config update due to change for {hostname}.")
            if update_cloudflare_config():
                logging.info(f"Cloudflare tunnel config update successful for {hostname}.")
                # After successful config update, ensure DNS record exists
                if tunnel_state.get("id"): # Ensure tunnel ID is available
                    logging.info(f"Attempting to create/verify DNS record for {hostname} in Zone ID {target_zone_id}...")
                    dns_record_id = create_cloudflare_dns_record(target_zone_id, hostname, tunnel_state["id"])
                    if dns_record_id:
                         logging.info(f"DNS record management in zone {target_zone_id} successful for {hostname}.")
                         # Optionally update last_action_status more specifically
                         # cloudflared_agent_state["last_action_status"] = f"Activated: {hostname} (DNS OK in {target_zone_id})"
                    else:
                         # CRITICAL: Tunnel config updated but DNS failed!
                         logging.error(f"CRITICAL: Tunnel config updated for {hostname} but failed to create/verify DNS record in zone {target_zone_id}! Manual intervention may be required.")
                         cloudflared_agent_state["last_action_status"] = f"Error: Failed creating DNS for {hostname} in zone {target_zone_id} after config update."
                else:
                     logging.error(f"Missing Tunnel ID - cannot manage DNS record for {hostname} after config update.")
                     cloudflared_agent_state["last_action_status"] = f"Error: Activated {hostname} but missing Tunnel ID for DNS."
            else:
                # update_cloudflare_config handles logging the failure
                logging.error(f"Failed to update Cloudflare tunnel config after processing start for {hostname}. DNS record not managed.")
                # cloudflared_agent_state["last_action_status"] = f"Error: Failed CF config update for {hostname}." # Already set by update_cloudflare_config
        elif state_changed_locally:
             # Only local state changed (e.g., container ID update)
             logging.debug(f"Local state updated for {hostname}, no Cloudflare config change needed.")

    except NotFound:
        # Should be caught by reload, but handle defensively
        logging.warning(f"Container {container_id[:12] if container_id else 'Unknown'} not found during start processing.")
    except APIError as e:
        logging.error(f"Docker API error processing container start ({container_name}/{container_id[:12] if container_id else 'Unknown'}): {e}", exc_info=True)
    except Exception as e:
        logging.error(f"Unexpected error processing container start ({container_name}/{container_id[:12] if container_id else 'Unknown'}): {e}", exc_info=True)


def schedule_container_stop(container_id):
    """Marks the rule associated with a stopped container for deletion after a grace period."""
    if not container_id:
        logging.debug("schedule_container_stop called with None container_id.")
        return

    logging.info(f"Processing stop event for container {container_id[:12]}.")
    hostname_to_schedule = None
    state_changed = False
    with state_lock:
        # Find the hostname managed by this container ID that is currently active
        for hn, details in managed_rules.items():
            if details.get("container_id") == container_id and details.get("status") == "active":
                hostname_to_schedule = hn
                break # Found the rule

        if hostname_to_schedule:
            rule = managed_rules[hostname_to_schedule]
            # Only schedule if not already pending (avoids resetting timer on rapid stop/start)
            if rule.get("status") != "pending_deletion":
                 logging.info(f"Container {container_id[:12]} managed active rule for {hostname_to_schedule}. Marking for deletion.")
                 rule["status"] = "pending_deletion"
                 # Calculate deletion time in UTC
                 delete_time_utc = datetime.now(timezone.utc) + timedelta(seconds=GRACE_PERIOD_SECONDS)
                 rule["delete_at"] = delete_time_utc
                 logging.info(f"Rule {hostname_to_schedule} scheduled for deletion at {delete_time_utc.isoformat()}")
                 state_changed = True
            else:
                 # Rule already pending, log but don't change anything
                 logging.info(f"Rule {hostname_to_schedule} (container {container_id[:12]}) already pending deletion. No action needed.")
        else:
            # Stop event for a container we didn't manage or whose rule was already pending/gone
            logging.debug(f"Stop event for container {container_id[:12]}, but it didn't manage an active rule in the current state.")

        # Save state if it changed
        if state_changed:
            save_state()


def docker_event_listener():
    """Listens for Docker container start/stop events and triggers processing."""
    if not docker_client:
        logging.error("Docker client unavailable, event listener cannot start.")
        return

    logging.info("Starting Docker event listener...")
    error_count = 0
    max_errors = 5 # Max consecutive errors before stopping listener
    reconnect_delay = 5 # Initial reconnect delay

    while not stop_event.is_set():
        try:
            logging.info("Connecting to Docker event stream...")
            # Listen for events from now onwards
            events = docker_client.events(decode=True, since=int(time.time()))
            logging.info("Successfully connected to Docker event stream. Listening...")
            error_count = 0 # Reset error count on successful connection
            reconnect_delay = 5 # Reset reconnect delay

            for event in events:
                if stop_event.is_set():
                    logging.info("Stop event received, exiting listener loop.")
                    break # Exit inner loop

                # Extract relevant event details safely
                event_type = event.get("Type")
                action = event.get("Action")
                actor = event.get("Actor", {})
                container_id = actor.get("ID")
                # container_name = actor.get("Attributes", {}).get("name") # Often useful for logs

                logging.debug(f"Docker Event: Type={event_type}, Action={action}, ID={container_id[:12] if container_id else 'N/A'}")

                if event_type == "container" and container_id:
                    if action == "start":
                        try:
                            # Get the container object to access labels etc.
                            container = docker_client.containers.get(container_id)
                            process_container_start(container)
                        except NotFound:
                            logging.warning(f"Container {container_id[:12]} not found immediately after 'start' event.")
                        except APIError as e:
                            logging.error(f"Docker API error processing start event for {container_id[:12]}: {e}")
                        except Exception as e:
                            # Catch broader errors in process_container_start
                            logging.error(f"Unexpected error processing start event for {container_id[:12]}: {e}", exc_info=True)

                    elif action in ["stop", "die", "destroy", "kill", "remove"]:
                        # Treat all these actions as indicators the container is gone/going
                        try:
                            schedule_container_stop(container_id)
                        except Exception as e:
                            logging.error(f"Unexpected error processing stop/die/etc. event for {container_id[:12]}: {e}", exc_info=True)

            # If the event stream ends unexpectedly (e.g., Docker daemon restart)
            logging.warning("Docker event stream ended unexpectedly. Attempting reconnect...")

        except requests.exceptions.ConnectionError as e:
            error_count += 1
            logging.error(f"Docker listener connection error ({error_count}/{max_errors}): {e}. Retrying in {reconnect_delay}s...")
            stop_event.wait(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 60) # Exponential backoff up to 60s
        except APIError as e:
            error_count += 1
            # Handle specific API errors if needed (e.g., auth failure)
            logging.error(f"Docker listener API error ({error_count}/{max_errors}): {e}. Retrying in {reconnect_delay}s...")
            stop_event.wait(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 60)
        except Exception as e:
            # Catch any other unexpected errors in the listener loop
            error_count += 1
            logging.error(f"Unexpected error in Docker listener ({error_count}/{max_errors}): {e}. Retrying in {reconnect_delay}s...", exc_info=True)
            stop_event.wait(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 60)

        # Check if max errors reached
        if error_count >= max_errors:
            logging.error(f"Docker event listener stopping after {max_errors} consecutive errors.")
            # Update state to reflect Docker unavailability if applicable
            if not docker_client or not docker_client.ping():
                 cloudflared_agent_state["container_status"] = "docker_unavailable"
            break # Exit outer loop

        # Check stop event again before looping
        if stop_event.is_set():
            logging.info("Stop event received, stopping listener.")
            break

    logging.info("Docker event listener stopped.")


def cleanup_expired_rules():
    """Periodically checks for rules marked 'pending_deletion' whose grace period has expired."""
    logging.info("Starting expired rule cleanup task...")
    while not stop_event.is_set():
        next_check_time = time.time() + CLEANUP_INTERVAL_SECONDS
        try:
            logging.debug("Running cleanup check for expired rules...")
            rules_requiring_action = {} # Store hostname -> zone_id for expired rules needing deletion
            now_utc = datetime.now(timezone.utc)
            state_changed_in_cleanup = False
            rules_actually_removed_from_state = [] # Track hostnames removed from state

            with state_lock:
                # Iterate over a copy of hostnames to allow modification of managed_rules
                for hostname in list(managed_rules.keys()):
                    details = managed_rules[hostname]
                    if details.get("status") == "pending_deletion":
                        delete_at_ts = details.get("delete_at")
                        is_expired = False

                        # Check if delete_at timestamp is valid and passed
                        if isinstance(delete_at_ts, datetime):
                             # Ensure timestamp is UTC (should be saved as UTC)
                             if delete_at_ts.tzinfo is None:
                                  # If loaded state had naive datetime, assume UTC
                                  delete_at_utc = delete_at_ts.replace(tzinfo=timezone.utc)
                                  logging.warning(f"Rule {hostname} had naive delete_at timestamp; assuming UTC: {delete_at_utc}")
                             else:
                                  delete_at_utc = delete_at_ts.astimezone(timezone.utc)

                             if delete_at_utc <= now_utc:
                                 is_expired = True
                        elif delete_at_ts: # Timestamp exists but isn't a datetime object
                             logging.warning(f"Rule {hostname} pending deletion has invalid delete_at type ({type(delete_at_ts)}): {delete_at_ts}. Treating as expired.")
                             is_expired = True # Treat invalid timestamp as expired
                        else: # Status is pending but no timestamp
                              logging.warning(f"Rule {hostname} pending deletion but missing delete_at timestamp. Treating as expired.")
                              is_expired = True # Treat missing timestamp as expired

                        if is_expired:
                            # Determine Zone ID for DNS deletion
                            zone_id_for_delete = details.get("zone_id") # Get from state first
                            if not zone_id_for_delete:
                                zone_id_for_delete = CF_ZONE_ID # Fallback to default env var
                                if zone_id_for_delete:
                                    logging.warning(f"Rule {hostname} missing zone_id in state, falling back to default CF_ZONE_ID {zone_id_for_delete} for DNS deletion.")
                                else:
                                    logging.error(f"Cannot perform DNS deletion for expired rule {hostname}: Zone ID is missing in state AND no default CF_ZONE_ID is set. Rule will be removed from state, but DNS may remain.")
                            # Store hostname and the determined zone_id (can be None)
                            rules_requiring_action[hostname] = zone_id_for_delete
                            logging.info(f"Rule for {hostname} (Zone: {zone_id_for_delete or 'Unknown/None'}) expired. Scheduling for full deletion.")

            # --- Process Deletions (outside lock) ---
            if rules_requiring_action:
                logging.info(f"Processing cleanup for {len(rules_requiring_action)} expired hostnames: {list(rules_requiring_action.keys())}")
                processed_hostnames_for_cf_update = []
                all_dns_deletes_successful_or_skipped = True

                # Step 1: Attempt DNS record deletion first (if zone_id is known)
                for hostname, zone_id in rules_requiring_action.items():
                    dns_delete_attempted = False
                    dns_delete_ok = True # Assume OK if skipped
                    if zone_id and tunnel_state.get("id"):
                         dns_delete_attempted = True
                         logging.info(f"Attempting DNS record deletion for expired rule: {hostname} in zone {zone_id}")
                         if not delete_cloudflare_dns_record(zone_id, hostname, tunnel_state["id"]):
                              logging.error(f"Failed to delete DNS record for {hostname} in zone {zone_id}. Tunnel config update will proceed, but DNS record may remain stale.")
                              all_dns_deletes_successful_or_skipped = False
                              dns_delete_ok = False # Mark specific failure
                         # If delete_cloudflare_dns_record returns True, dns_delete_ok remains True
                    elif not zone_id:
                         logging.info(f"Skipping DNS deletion for {hostname} as Zone ID was not determined.")
                         # Keep all_dns_deletes_successful_or_skipped = True (skipped isn't a failure)
                    else: # Missing tunnel ID
                         logging.error(f"Cannot attempt DNS deletion for {hostname}: Missing Tunnel ID.")
                         all_dns_deletes_successful_or_skipped = False # Cannot guarantee DNS state
                         dns_delete_ok = False # Mark failure due to inability to attempt

                    # Regardless of DNS outcome, plan to remove from state and potentially CF config
                    processed_hostnames_for_cf_update.append(hostname)

                # Step 2: Remove rules from local state (do this *before* CF update)
                # This ensures if CF update fails repeatedly, reconciliation won't immediately
                # try to re-add these expired rules based on old state.
                if processed_hostnames_for_cf_update:
                     with state_lock:
                          deleted_count = 0
                          for hostname in processed_hostnames_for_cf_update:
                               if hostname in managed_rules and managed_rules[hostname].get("status") == "pending_deletion":
                                   # Only delete if it's still marked as pending, guarding against race conditions
                                   del managed_rules[hostname]
                                   deleted_count += 1
                                   state_changed_in_cleanup = True
                                   rules_actually_removed_from_state.append(hostname)
                               elif hostname in managed_rules:
                                    logging.warning(f"Rule {hostname} was scheduled for cleanup deletion, but status was '{managed_rules[hostname].get('status')}' (not pending_deletion) when removing from state. Removing anyway.")
                                    del managed_rules[hostname] # Remove even if status changed unexpectedly
                                    deleted_count += 1
                                    state_changed_in_cleanup = True
                                    rules_actually_removed_from_state.append(hostname)
                               else:
                                   logging.warning(f"Rule {hostname} scheduled for cleanup removal but was already gone from state.")
                          if deleted_count > 0:
                               logging.info(f"Removed {deleted_count} rules from local state during cleanup: {rules_actually_removed_from_state}")
                          if state_changed_in_cleanup:
                               save_state() # Save the updated state

                # Step 3: Update Cloudflare tunnel config (reflects removal from active rules)
                # Only trigger if the state actually changed by removing rules
                if state_changed_in_cleanup:
                    logging.info(f"Attempting Cloudflare tunnel config update after removing rules from state: {rules_actually_removed_from_state}")
                    if update_cloudflare_config():
                        logging.info(f"Cloudflare tunnel config updated successfully following cleanup.")
                        action_msg = f"Cleaned up {len(rules_actually_removed_from_state)} rules. DNS OK: {all_dns_deletes_successful_or_skipped}"
                        # cloudflared_agent_state["last_action_status"] = action_msg[:250] # Optional status update
                    else:
                        # CF update failed, but state is already updated. Reconciliation should eventually fix CF.
                        logging.error("Failed to update Cloudflare tunnel config during rule cleanup. State already updated. Reconciliation needed for tunnel config.")
                        action_msg = f"Error: Cleaned {len(rules_actually_removed_from_state)} rules but FAILED CF update. DNS OK: {all_dns_deletes_successful_or_skipped}"
                        # cloudflared_agent_state["last_action_status"] = action_msg[:250] # Optional status update
                else:
                     # This branch might be reached if rules_requiring_action was populated
                     # but the rules were somehow removed from state before Step 2.
                     logging.debug("No state changes occurred during cleanup processing, skipping Cloudflare config update.")

            else:
                # No rules were found to be expired in this check
                logging.debug("No expired rules found requiring cleanup.")

        except Exception as e:
            # Catch unexpected errors in the cleanup loop itself
            logging.error(f"Error in cleanup task loop: {e}", exc_info=True)

        # Wait for the next interval or until stop event signals shutdown
        # Use max(0, ...) in case calculation yields negative due to long processing time
        wait_duration = max(0, next_check_time - time.time())
        stop_event.wait(wait_duration)

    logging.info("Expired rule cleanup task stopped.")


def reconcile_state():
    """Compares Docker state, local state, and Cloudflare config to ensure consistency."""
    if not docker_client:
        logging.warning("Docker client unavailable, skipping state reconciliation.")
        return
    if not tunnel_state.get("id"):
        logging.warning("Tunnel not initialized (missing ID), skipping state reconciliation.")
        return

    logging.info("Starting state reconciliation...")
    needs_cf_update = False
    state_changed_locally = False
    # Store hostname -> zone_id mapping for rules needing DNS check/create after potential CF update
    hostnames_requiring_dns_check = {}

    try:
        # --- Step 1: Get Current Docker State (Running Containers with Labels) ---
        running_labeled_containers = {} # hostname -> {details}
        try:
             # List only running containers
             containers = docker_client.containers.list(all=False, sparse=False)
             logging.debug(f"[Reconcile] Found {len(containers)} running containers.")
             for c in containers:
                 container_id = c.id
                 container_name = "N/A"
                 try:
                     # Reload to get potentially updated labels/status
                     c.reload()
                     container_name = c.name
                     labels = c.labels

                     # Extract labels
                     enabled = labels.get(LABEL_ENABLE, "false").lower() in ["true", "1", "t", "yes", "y"]
                     hostname = labels.get(LABEL_HOSTNAME)
                     service = labels.get(LABEL_SERVICE)
                     zone_name = labels.get(LABEL_ZONE_NAME)

                     # Basic validation
                     if enabled and hostname and service:
                         if not re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$", hostname):
                             logging.warning(f"[Reconcile] Skipping container {container_name} ({container_id[:12]}): Invalid hostname format '{hostname}'.")
                             continue
                         if not (re.match(r"^(https?|tcp|unix)://.+", service) or re.match(r"^[a-zA-Z0-9._-]+:\d+$", service)):
                              logging.warning(f"[Reconcile] Skipping container {container_name} ({container_id[:12]}): Invalid service format '{service}'.")
                              continue

                         # Check for duplicate hostnames from different containers
                         if hostname in running_labeled_containers:
                              logging.warning(f"[Reconcile] Duplicate hostname '{hostname}' detected. Container '{container_name}' ({container_id[:12]}) overwrites config from '{running_labeled_containers[hostname]['container_name']}' ({running_labeled_containers[hostname]['container_id'][:12]}).")

                         running_labeled_containers[hostname] = {
                             "service": service,
                             "container_id": container_id,
                             "container_name": container_name,
                             "zone_name": zone_name # Store zone name from label (can be None)
                         }
                 except (NotFound, APIError) as e:
                     # Handle errors fetching details for a specific container
                     logging.warning(f"[Reconcile] Error processing running container {container_id[:12]}: {e}. Skipping this container.")
                     continue # Skip to the next container
             logging.info(f"[Reconcile] Found {len(running_labeled_containers)} running containers with valid required labels.")
        except (APIError, requests.exceptions.ConnectionError) as e:
             # Handle errors listing containers (e.g., Docker daemon down)
             logging.error(f"[Reconcile] Docker error listing containers: {e}. Aborting reconciliation.")
             return # Cannot proceed without container list

        # --- Step 2: Compare Docker State with Local State (inside lock) ---
        with state_lock:
            logging.debug("[Reconcile] Acquired state lock for comparison.")
            now_utc = datetime.now(timezone.utc)
            # Get copies for safe iteration/comparison
            managed_hostnames_in_state = list(managed_rules.keys())
            running_hostnames_from_docker = set(running_labeled_containers.keys())

            # --- Sub-Step 2a: Check containers currently running ---
            for hostname, running_details in running_labeled_containers.items():
                # Determine the Zone ID expected for this running container
                target_zone_id = None
                zone_name = running_details.get("zone_name")
                zone_lookup_source = "N/A"
                if zone_name:
                    zone_lookup_source = f"label '{LABEL_ZONE_NAME}'='{zone_name}'"
                    target_zone_id = get_zone_id_from_name(zone_name) # Use cached lookup
                    if not target_zone_id:
                        logging.error(f"[Reconcile] Cannot manage DNS for running container {running_details['container_name']} ({hostname}): Failed lookup for zone name '{zone_name}' specified in label. Skipping this rule.")
                        continue # Skip processing this hostname if zone is invalid
                else:
                    target_zone_id = CF_ZONE_ID # Fallback to default env var
                    zone_lookup_source = f"default CF_ZONE_ID env var ({'Set' if CF_ZONE_ID else 'Not Set'})"

                # Final check if a Zone ID was determined
                if not target_zone_id:
                     logging.error(f"[Reconcile] Skipping management for running container {running_details['container_name']} ({hostname}): No valid Zone ID determined. Source checked: {zone_lookup_source}. Ensure label is correct or CF_ZONE_ID is set.")
                     continue # Skip processing this hostname

                # Compare with local state for this hostname
                if hostname in managed_rules:
                    # Rule exists in local state, check for updates
                    rule = managed_rules[hostname]
                    current_zone_id_in_state = rule.get("zone_id")
                    zone_id_changed = current_zone_id_in_state != target_zone_id

                    if rule.get("status") == "pending_deletion":
                        logging.info(f"[Reconcile] Hostname {hostname} is running again, reactivating pending rule.")
                        rule["status"] = "active"
                        rule["delete_at"] = None
                        rule["service"] = running_details["service"]
                        rule["container_id"] = running_details["container_id"]
                        rule["zone_id"] = target_zone_id # Update zone ID
                        state_changed_locally = True
                        needs_cf_update = True # Config needs update
                        hostnames_requiring_dns_check[hostname] = target_zone_id # Mark for DNS check
                        if zone_id_changed: logging.info(f"[Reconcile] Zone ID for reactivated {hostname} updated from '{current_zone_id_in_state}' to '{target_zone_id}'.")

                    elif rule.get("status") == "active":
                        # Rule already active, check for changes in service, container, or zone
                        container_changed = rule.get("container_id") != running_details["container_id"]
                        service_changed = rule.get("service") != running_details["service"]

                        if container_changed:
                            logging.info(f"[Reconcile] Updating container ID for active rule {hostname}.")
                            rule["container_id"] = running_details["container_id"]
                            state_changed_locally = True
                        if service_changed:
                            logging.info(f"[Reconcile] Updating service for active rule {hostname}.")
                            rule["service"] = running_details["service"]
                            state_changed_locally = True
                            needs_cf_update = True # Service change needs CF update
                        if zone_id_changed:
                             logging.warning(f"[Reconcile] Zone ID for active rule {hostname} changed ('{current_zone_id_in_state}' -> '{target_zone_id}'). Updating state. DNS in old zone may be stale.")
                             rule["zone_id"] = target_zone_id
                             state_changed_locally = True
                             # Mark for DNS check in the new zone
                             hostnames_requiring_dns_check[hostname] = target_zone_id

                else:
                    # New rule: Container running with labels, but not in our state yet
                    logging.info(f"[Reconcile] Found running container for new hostname {hostname}. Adding rule with Zone ID {target_zone_id}.")
                    managed_rules[hostname] = {
                        "service": running_details["service"],
                        "container_id": running_details["container_id"],
                        "status": "active",
                        "delete_at": None,
                        "zone_id": target_zone_id
                    }
                    state_changed_locally = True
                    needs_cf_update = True # New rule needs CF update
                    hostnames_requiring_dns_check[hostname] = target_zone_id # Mark for DNS creation

            # --- Sub-Step 2b: Check rules in state against containers currently running ---
            for hostname in managed_hostnames_in_state:
                if hostname not in running_hostnames_from_docker:
                     # Rule exists in our state, but no running container claims this hostname
                     if hostname in managed_rules: # Double-check it wasn't deleted in 2a
                         rule = managed_rules[hostname]
                         if rule.get("status") == "active":
                              # Found an active rule with no corresponding running container
                              logging.info(f"[Reconcile] Rule {hostname} is active in state but no container running for it. Scheduling for deletion (Grace: {GRACE_PERIOD_SECONDS}s).")
                              rule["status"] = "pending_deletion"
                              rule["delete_at"] = now_utc + timedelta(seconds=GRACE_PERIOD_SECONDS)
                              state_changed_locally = True
                              # No immediate CF update needed here; cleanup task handles pending deletions.
                         # If rule is already 'pending_deletion', leave it to the cleanup task.

            # --- Sub-Step 2c: Compare Local State (Active Rules) with Cloudflare Config (Sanity Check) ---
            # This helps catch drift if external changes were made to the tunnel config.
            logging.debug("[Reconcile] Fetching current CF config for ingress rule sanity check...")
            current_cf_config = get_current_cf_config() # Fetch config again (might have changed)
            if current_cf_config is not None:
                try:
                    # Get hostnames from CF config, excluding the catch-all
                    cf_ingress_hostnames = {
                        r.get("hostname") for r in current_cf_config.get("ingress", [])
                        if r.get("hostname") and r.get("service") != "http_status:404"
                    }
                    # Get hostnames that should be active according to our *current* state (after updates above)
                    active_managed_hostnames_final = {
                        hn for hn, d in managed_rules.items() if d.get("status") == "active"
                    }

                    # Compare the sets of hostnames
                    if cf_ingress_hostnames != active_managed_hostnames_final:
                         logging.warning(f"[Reconcile] Mismatch detected between active rules in final local state and Cloudflare tunnel config!")
                         logging.info(f"[Reconcile] State Active Hostnames ({len(active_managed_hostnames_final)}): {sorted(list(active_managed_hostnames_final))}")
                         logging.info(f"[Reconcile] Cloudflare Config Hostnames ({len(cf_ingress_hostnames)}): {sorted(list(cf_ingress_hostnames))}")
                         logging.info("[Reconcile] Forcing Cloudflare config update to match local state.")
                         needs_cf_update = True # Force update to align CF config with reconciled state
                    else:
                         logging.debug("[Reconcile] Local state active rules match Cloudflare tunnel config.")
                except Exception as e:
                    logging.error(f"[Reconcile] Error comparing final state with CF config: {e}", exc_info=True)
            else:
                logging.error("[Reconcile] Could not fetch CF config for final sanity check. Skipping ingress rule comparison.")

            # Save state file if any changes were made within the lock
            if state_changed_locally:
                logging.info("[Reconcile] Saving local state changes made during reconciliation.")
                save_state()

            logging.debug("[Reconcile] Releasing state lock.")

        # --- Step 3: Trigger Updates (outside lock) ---
        if needs_cf_update:
            logging.info("[Reconcile] Triggering Cloudflare tunnel config update based on reconciliation results.")
            if update_cloudflare_config():
                 logging.info("[Reconcile] Cloudflare tunnel config update successful.")
                 # After successful CF update, perform necessary DNS checks/creations
                 if hostnames_requiring_dns_check:
                      logging.info(f"[Reconcile] Checking/Creating DNS records for {len(hostnames_requiring_dns_check)} new/reactivated/zone-changed rules: {list(hostnames_requiring_dns_check.keys())}")
                      dns_check_all_ok = True
                      for hostname, zone_id_to_use in hostnames_requiring_dns_check.items():
                           if zone_id_to_use and tunnel_state.get("id"):
                                if not create_cloudflare_dns_record(zone_id_to_use, hostname, tunnel_state["id"]):
                                     # Log critical error, but continue checking others
                                     logging.error(f"[Reconcile] CRITICAL: Failed DNS check/create for {hostname} in zone {zone_id_to_use} after successful tunnel config update!")
                                     dns_check_all_ok = False
                           else:
                                # Log error if zone_id or tunnel_id is missing
                                logging.error(f"[Reconcile] Cannot check/create DNS for {hostname}: Missing Zone ID ('{zone_id_to_use}') or Tunnel ID ('{tunnel_state.get('id')}').")
                                dns_check_all_ok = False

                      if dns_check_all_ok:
                           logging.info("[Reconcile] All required DNS checks/creations completed successfully.")
                           cloudflared_agent_state["last_action_status"] = f"Reconcile OK: CF config updated, DNS checks passed ({datetime.now(timezone.utc).strftime('%H:%M:%S')})"
                      else:
                           cloudflared_agent_state["last_action_status"] = f"Reconcile Warning: CF config updated, but some DNS checks failed ({datetime.now(timezone.utc).strftime('%H:%M:%S')})"
                 else:
                      # CF update happened, but no specific DNS checks were triggered by reconcile
                      logging.info("[Reconcile] Cloudflare config updated (no new DNS checks triggered by reconcile).")
                      cloudflared_agent_state["last_action_status"] = f"Reconcile OK: CF config updated ({datetime.now(timezone.utc).strftime('%H:%M:%S')})"
            else:
                # update_cloudflare_config failed
                logging.error("[Reconcile] Failed Cloudflare tunnel config update during reconcile. DNS checks skipped.")
                # last_action_status should have been set by update_cloudflare_config failure
        elif state_changed_locally:
            # Only local state changes (e.g., container ID, scheduling delete)
            logging.info("[Reconcile] Reconciliation resulted in local state changes only.")
        else:
            # No changes needed at all
            logging.info("[Reconcile] No changes required based on reconciliation.")

    except Exception as e:
        # Catch unexpected errors during the main reconciliation flow
        logging.error(f"Unexpected error during reconcile process: {e}", exc_info=True)
    finally:
        logging.info("Reconciliation process finished.")


# --- Cloudflared Agent Container Management ---

def get_cloudflared_container():
    """Gets the Docker container object for the cloudflared agent."""
    if not docker_client:
        logging.warning("Docker client unavailable, cannot get agent container.")
        # Update state if Docker was previously available
        if cloudflared_agent_state["container_status"] != "docker_unavailable":
             cloudflared_agent_state["container_status"] = "docker_unavailable"
             cloudflared_agent_state["last_action_status"] = "Error: Lost connection to Docker."
        return None

    try:
        container = docker_client.containers.get(CLOUDFLARED_CONTAINER_NAME)
        return container
    except NotFound:
        logging.debug(f"Agent container '{CLOUDFLARED_CONTAINER_NAME}' not found.")
        if cloudflared_agent_state["container_status"] != "not_found":
             # Update status only if it wasn't already known to be missing
             cloudflared_agent_state["container_status"] = "not_found"
        return None
    except APIError as e:
        logging.error(f"Docker API error getting agent container '{CLOUDFLARED_CONTAINER_NAME}': {e}")
        cloudflared_agent_state["last_action_status"] = f"Error getting agent container: {e}"
        # Consider setting status to unknown or error state?
        cloudflared_agent_state["container_status"] = "unknown"
        return None
    except requests.exceptions.ConnectionError as e:
        # Lost connection to Docker daemon
        logging.error(f"Docker connection error getting agent container: {e}")
        cloudflared_agent_state["container_status"] = "docker_unavailable"
        cloudflared_agent_state["last_action_status"] = "Error: Lost connection to Docker."
        # Set docker_client to None to prevent further attempts until reconnected
        global docker_client
        docker_client = None
        return None
    except Exception as e:
        # Catch unexpected errors
        logging.error(f"Unexpected error getting agent container '{CLOUDFLARED_CONTAINER_NAME}': {e}", exc_info=True)
        cloudflared_agent_state["last_action_status"] = f"Error: Unexpected error getting agent: {e}"
        cloudflared_agent_state["container_status"] = "unknown"
        return None


def update_cloudflared_container_status():
    """Updates the global state with the current status of the agent container."""
    global docker_client # Allow potentially resetting docker_client if connection lost
    if not docker_client:
        # Attempt to reconnect if client is None
        logging.debug("Docker client unavailable, attempting reconnect for status update...")
        try:
            docker_client = docker.from_env(timeout=5)
            docker_client.ping()
            logging.info("Reconnected to Docker daemon for status update.")
            # If reconnected, proceed to get container status
            # Fall through to the get_cloudflared_container() call
        except Exception as e:
            logging.warning(f"Reconnect to Docker failed during status update: {e}")
            if cloudflared_agent_state["container_status"] != "docker_unavailable":
                 cloudflared_agent_state["container_status"] = "docker_unavailable"
                 cloudflared_agent_state["last_action_status"] = "Error: Lost connection to Docker."
            docker_client = None # Ensure it remains None
            return # Cannot update status without connection

    # --- Get container and update status ---
    container = get_cloudflared_container() # This handles errors and updates status if unavailable/not found

    if container:
        try:
            # Reload container state for accuracy
            container.reload()
            new_status = container.status # e.g., 'running', 'exited', 'created'
            # Update global state only if status changed
            if cloudflared_agent_state.get("container_status") != new_status:
                 logging.info(f"Agent container '{CLOUDFLARED_CONTAINER_NAME}' status changed to: {new_status}")
                 cloudflared_agent_state["container_status"] = new_status
                 # Clear last action status if container is now running (implies success)
                 if new_status == 'running':
                      cloudflared_agent_state["last_action_status"] = None
            # else: # Status hasn't changed
            #      logging.debug(f"Agent container status remains: {new_status}")

        except (NotFound, APIError) as e:
             # Container disappeared between get() and reload()
             logging.warning(f"Error reloading agent container status (container likely removed): {e}")
             if cloudflared_agent_state["container_status"] != "not_found":
                 cloudflared_agent_state["container_status"] = "not_found"
                 cloudflared_agent_state["last_action_status"] = "Agent container disappeared."
        except requests.exceptions.ConnectionError as e:
             # Lost connection during reload
             logging.error(f"Docker connection error updating agent status: {e}")
             cloudflared_agent_state["container_status"] = "docker_unavailable"
             cloudflared_agent_state["last_action_status"] = "Error: Lost connection to Docker."
             docker_client = None # Mark client as unusable
        except Exception as e:
             logging.error(f"Unexpected error reloading agent container status: {e}", exc_info=True)
             cloudflared_agent_state["container_status"] = "unknown" # Mark as unknown due to error
    # else: # container is None
         # get_cloudflared_container already updated the status (not_found or docker_unavailable)
         # logging.debug("Agent container not found or Docker unavailable.")
         pass


def ensure_docker_network_exists(network_name):
     """Checks if the specified Docker network exists, creates it if not."""
     if not docker_client:
         logging.error(f"Docker client unavailable, cannot check or create network '{network_name}'.")
         return False

     try:
         # Attempt to get the network
         docker_client.networks.get(network_name)
         logging.info(f"Docker network '{network_name}' already exists.")
         return True
     except NotFound:
         # Network doesn't exist, try to create it
         logging.info(f"Docker network '{network_name}' not found. Creating...")
         try:
             # Create a standard bridge network
             network = docker_client.networks.create(network_name, driver="bridge", check_duplicate=True)
             logging.info(f"Successfully created Docker network '{network_name}' (ID: {network.id}).")
             return True
         except APIError as create_err:
             # Handle potential race condition if network created between get() and create()
             if "already exists" in str(create_err):
                 logging.warning(f"Network '{network_name}' seems to have been created concurrently (API error: {create_err}). Assuming success.")
                 return True
             else:
                 # Log other creation errors
                 logging.error(f"Failed to create Docker network '{network_name}': {create_err}", exc_info=True)
                 cloudflared_agent_state["last_action_status"] = f"Error creating network '{network_name}': {create_err}"
                 return False
         except Exception as e:
              logging.error(f"Unexpected error creating network '{network_name}': {e}", exc_info=True)
              cloudflared_agent_state["last_action_status"] = f"Error creating network '{network_name}': {e}"
              return False
     except APIError as get_err:
         # Handle errors during the initial get() call
         logging.error(f"API error checking for network '{network_name}': {get_err}", exc_info=True)
         cloudflared_agent_state["last_action_status"] = f"Error checking network '{network_name}': {get_err}"
         return False
     except requests.exceptions.ConnectionError as e:
         logging.error(f"Docker connection error checking network '{network_name}': {e}")
         cloudflared_agent_state["last_action_status"] = f"Error: Docker connection lost checking network."
         global docker_client
         docker_client = None # Mark as unavailable
         return False
     except Exception as e:
          logging.error(f"Unexpected error checking network '{network_name}': {e}", exc_info=True)
          cloudflared_agent_state["last_action_status"] = f"Error checking network '{network_name}': {e}"
          return False


def start_cloudflared_container():
    """Starts the cloudflared agent container if not already running."""
    logging.info(f"Attempting to start agent container '{CLOUDFLARED_CONTAINER_NAME}'...")
    cloudflared_agent_state["last_action_status"] = "Starting agent..."
    start_successful = False

    # Pre-checks
    if not docker_client:
        msg = "Docker client not available."
        logging.error(msg)
        cloudflared_agent_state["last_action_status"] = f"Error: {msg}"
        return False
    if not tunnel_state.get("token"):
        msg = "Tunnel token not available (tunnel initialization failed?)."
        logging.error(msg)
        cloudflared_agent_state["last_action_status"] = f"Error: {msg} Cannot start agent."
        return False

    try:
        # Ensure the target Docker network exists *before* trying to use it
        if not ensure_docker_network_exists(CLOUDFLARED_NETWORK_NAME):
             # ensure_docker_network_exists already logged the error and set status
             logging.error(f"Failed network check/create for '{CLOUDFLARED_NETWORK_NAME}'. Cannot start agent container.")
             # Ensure status reflects this if function didn't set it (shouldn't be needed)
             if not cloudflared_agent_state.get("last_action_status") or "network" not in cloudflared_agent_state["last_action_status"].lower():
                 cloudflared_agent_state["last_action_status"] = f"Error: Failed network setup for {CLOUDFLARED_NETWORK_NAME}"
             return False

        # Get the tunnel token
        token = tunnel_state["token"]

        # Check if container exists
        container = get_cloudflared_container()
        needs_recreate = False

        if container:
             try:
                 container.reload() # Get current status
                 logging.info(f"Found existing agent container '{CLOUDFLARED_CONTAINER_NAME}' with status: {container.status}")

                 if container.status == 'running':
                     msg = f"Agent container '{CLOUDFLARED_CONTAINER_NAME}' is already running."
                     logging.info(msg)
                     cloudflared_agent_state["last_action_status"] = msg
                     cloudflared_agent_state["container_status"] = "running" # Ensure state matches
                     start_successful = True
                     return True # Already running, success

                 # --- Configuration Check (Example: Network) ---
                 # Check if it's connected to the correct network
                 current_networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})
                 if CLOUDFLARED_NETWORK_NAME not in current_networks:
                      logging.warning(f"Existing container '{CLOUDFLARED_CONTAINER_NAME}' is not in the expected network '{CLOUDFLARED_NETWORK_NAME}'. It needs to be recreated.")
                      needs_recreate = True
                 # Add other checks if necessary (e.g., image version, command)

                 # --- Recreate if needed ---
                 if needs_recreate:
                      logging.info(f"Removing misconfigured/stopped container '{CLOUDFLARED_CONTAINER_NAME}' before recreating...")
                      try:
                          container.remove(force=True) # Force remove if stopped
                          container = None # Mark as removed
                          logging.info(f"Successfully removed container '{CLOUDFLARED_CONTAINER_NAME}'.")
                      except (APIError, requests.exceptions.ConnectionError) as rm_err:
                          logging.error(f"Failed to remove misconfigured/stopped container '{CLOUDFLARED_CONTAINER_NAME}': {rm_err}. Start aborted.")
                          cloudflared_agent_state["last_action_status"] = f"Error: Failed remove old agent: {rm_err}"
                          return False # Abort start if removal fails
                 else:
                      # Container exists, is stopped, and config seems okay - try starting it
                      logging.info(f"Starting existing (stopped) container '{CLOUDFLARED_CONTAINER_NAME}'...")
                      container.start()
                      msg = f"Started existing container '{CLOUDFLARED_CONTAINER_NAME}'."
                      cloudflared_agent_state["last_action_status"] = msg
                      logging.info(msg)
                      start_successful = True
                      # Status will be updated after a short delay below

             except (NotFound, APIError) as e:
                 # Error checking existing container, assume it's gone/unusable
                 logging.warning(f"Error checking existing container '{CLOUDFLARED_CONTAINER_NAME}': {e}. Assuming creation is needed.")
                 container = None # Mark as needing creation
             except requests.exceptions.ConnectionError as e:
                 # Handle connection error during check
                 logging.error(f"Docker connection error checking existing container: {e}")
                 cloudflared_agent_state["last_action_status"] = f"Error: Docker connection lost checking agent."
                 global docker_client
                 docker_client = None # Mark unusable
                 return False

        # --- Create Container if it doesn't exist or needed recreation ---
        if not container and not start_successful: # Only create if not found/removed AND not already started
            logging.info(f"Agent container '{CLOUDFLARED_CONTAINER_NAME}' not found or removed. Creating and starting...")
            try:
                # Pull the latest image first (optional but recommended)
                try:
                    logging.info(f"Pulling agent image '{CLOUDFLARED_IMAGE}'...")
                    docker_client.images.pull(CLOUDFLARED_IMAGE)
                    logging.info(f"Successfully pulled image '{CLOUDFLARED_IMAGE}'.")
                except APIError as img_err:
                    # Log warning but continue, Docker will try pulling during run if needed
                    logging.warning(f"Could not pull image '{CLOUDFLARED_IMAGE}': {img_err}. Docker run command will attempt to pull.")
                except requests.exceptions.ConnectionError as e:
                    logging.error(f"Docker connection failed during image pull: {e}")
                    cloudflared_agent_state["last_action_status"] = f"Error: Docker connection lost pulling image."
                    global docker_client
                    docker_client = None
                    return False

                # Define container parameters
                container_params = {
                    "image": CLOUDFLARED_IMAGE,
                    "command": f"tunnel --no-autoupdate run --token {token}",
                    "name": CLOUDFLARED_CONTAINER_NAME,
                    "network": CLOUDFLARED_NETWORK_NAME,
                    "restart_policy": {"Name": "unless-stopped"},
                    "detach": True,
                    "remove": False, # Don't auto-remove, we might want logs
                    "labels": {
                        "managed-by": "cloudflare-tunnel-ingress-controller",
                        "dev.opsmx.cloudflare-tunnel-ingress-controller.tunnel-name": TUNNEL_NAME
                        }
                }
                # Run the container
                new_container = docker_client.containers.run(**container_params)
                msg = f"Successfully created and started agent container '{new_container.name}' (ID: {new_container.id[:12]})."
                cloudflared_agent_state["last_action_status"] = msg
                logging.info(msg)
                start_successful = True

            except APIError as create_err:
                # Handle specific errors like name conflict
                if "Conflict" in str(create_err) and "is already in use" in str(create_err):
                    logging.error(f"Container name '{CLOUDFLARED_CONTAINER_NAME}' is already in use by another container. Please remove the conflicting container manually.")
                    msg = f"Error: Container name '{CLOUDFLARED_CONTAINER_NAME}' conflict. Remove manually & retry."
                else:
                    # Log other API errors during creation
                    msg = f"Docker API error creating container: {create_err}"
                    logging.error(msg, exc_info=True)
                cloudflared_agent_state["last_action_status"] = msg
                start_successful = False
            except requests.exceptions.ConnectionError as e:
                # Handle connection error during run
                logging.error(f"Docker connection failed running container: {e}")
                cloudflared_agent_state["last_action_status"] = f"Error: Docker connection lost running agent."
                global docker_client
                docker_client = None
                start_successful = False
            except Exception as e:
                 # Catch unexpected errors during creation/start
                 msg = f"Unexpected error creating/starting container: {e}"
                 logging.error(msg, exc_info=True)
                 cloudflared_agent_state["last_action_status"] = f"Error: {msg}"
                 start_successful = False

    except Exception as e:
        # Catch unexpected errors in the overall start sequence
        msg = f"Unexpected error during start agent sequence: {e}"
        logging.error(msg, exc_info=True)
        cloudflared_agent_state["last_action_status"] = f"Error: {msg}"
        start_successful = False
    finally:
        # Update the status after a short delay to allow container to settle
        if docker_client:
            logging.debug("Updating agent status shortly after start attempt...")
            time.sleep(2) # Give agent time to potentially start/fail
            update_cloudflared_container_status()
        logging.info(f"Exiting start_cloudflared_container function (Success: {start_successful}).")
        return start_successful


def stop_cloudflared_container():
    """Stops the cloudflared agent container if it's running."""
    logging.info(f"Attempting to stop agent container '{CLOUDFLARED_CONTAINER_NAME}'...")
    cloudflared_agent_state["last_action_status"] = "Stopping agent..."
    stop_successful = False

    if not docker_client:
        msg = "Docker client not available."
        logging.error(msg)
        cloudflared_agent_state["last_action_status"] = f"Error: {msg}"
        return False

    try:
        container = get_cloudflared_container()

        if not container:
            # Container doesn't exist
            msg = f"Agent container '{CLOUDFLARED_CONTAINER_NAME}' not found (already stopped or never created)."
            logging.warning(msg)
            cloudflared_agent_state["last_action_status"] = msg
            cloudflared_agent_state["container_status"] = "not_found" # Ensure state matches
            stop_successful = True
            return True # Considered success as it's not running

        # Container exists, check status
        container.reload()
        if container.status != 'running':
            msg = f"Agent container '{CLOUDFLARED_CONTAINER_NAME}' is not running (status: {container.status})."
            logging.info(msg)
            cloudflared_agent_state["last_action_status"] = msg
            cloudflared_agent_state["container_status"] = container.status # Update state
            stop_successful = True
            return True # Considered success as it's not running

        # Container is running, attempt to stop it
        logging.info(f"Stopping running agent container '{CLOUDFLARED_CONTAINER_NAME}'...")
        # Use a reasonable timeout for graceful shutdown
        container.stop(timeout=30)
        msg = f"Successfully stopped agent container '{CLOUDFLARED_CONTAINER_NAME}'."
        cloudflared_agent_state["last_action_status"] = msg
        logging.info(msg)
        stop_successful = True
        # Status will be updated after delay below

    except (APIError, NotFound) as e:
        # Handle errors during stop (e.g., container disappeared between get and stop)
        msg = f"Docker API error stopping container: {e}"
        logging.error(msg, exc_info=True)
        cloudflared_agent_state["last_action_status"] = f"Error: {msg}"
        stop_successful = False
    except requests.exceptions.ConnectionError as e:
        # Handle connection error during stop
        msg = f"Docker connection error stopping container: {e}"
        logging.error(msg)
        cloudflared_agent_state["last_action_status"] = f"Error: {msg}"
        global docker_client
        docker_client = None # Mark unusable
        stop_successful = False
    except Exception as e:
        # Catch unexpected errors during stop sequence
        msg = f"Unexpected error stopping container: {e}"
        logging.error(msg, exc_info=True)
        cloudflared_agent_state["last_action_status"] = f"Error: {msg}"
        stop_successful = False
    finally:
        # Update status after a short delay
        if docker_client:
            logging.debug("Updating agent status shortly after stop attempt...")
            time.sleep(2)
            update_cloudflared_container_status()
        logging.info(f"Exiting stop_cloudflared_container function (Success: {stop_successful}).")
        return stop_successful


# --- Flask Web UI ---
app = Flask(__name__)
# Use environment variable for secret key in production, fallback for dev
app.secret_key = os.getenv('FLASK_SECRET_KEY')
if not app.secret_key:
     logging.warning("FLASK_SECRET_KEY environment variable not set. Using a temporary random key. Flash messages will not persist across restarts.")
     app.secret_key = os.urandom(24)


def get_display_token(token):
    """Returns a masked version of the token for display."""
    if not token:
        return "Not Available"
    if len(token) > 10:
        return f"{token[:5]}...{token[-5:]}"
    else:
        # Should not happen with real tokens, but handle short strings
        return "Token Retrieved (Short)"


@app.route('/')
def status_page():
    """Renders the main status page."""
    # Always update agent status before rendering the page
    update_cloudflared_container_status()

    # Prepare data for the template safely
    with state_lock:
        # Create copies of state dicts for thread safety
        template_tunnel_state = tunnel_state.copy()
        template_agent_state = cloudflared_agent_state.copy()
        # Deep copy rules for rendering to avoid modification issues
        # Using json load/dump is a simple way for basic data types
        try:
            rules_for_template = json.loads(json.dumps(managed_rules, default=str))
        except Exception:
             logging.error("Failed to serialize managed_rules for template. Displaying empty.", exc_info=True)
             rules_for_template = {}
        # Get the current grace period (which might have been updated)
        current_grace_period_seconds = GRACE_PERIOD_SECONDS

    display_token = get_display_token(template_tunnel_state.get("token"))
    docker_available = docker_client is not None

    # Convert grace period to hours for display
    grace_period_hours = round(current_grace_period_seconds / 3600.0, 2)

    return render_template('status_page.html',
                            tunnel_state=template_tunnel_state,
                            agent_state=template_agent_state,
                            display_token=display_token,
                            cloudflared_container_name=CLOUDFLARED_CONTAINER_NAME,
                            docker_available=docker_available,
                            rules=rules_for_template,
                            grace_period_hours=grace_period_hours)


@app.route('/start', methods=['POST'])
def start_tunnel():
    """Flask route to handle starting the agent via UI button."""
    logging.info("UI request received: Start tunnel agent.")
    if start_cloudflared_container():
        flash("Tunnel agent starting process initiated.", "info")
    else:
        # start_cloudflared_container already set last_action_status with error details
        flash(f"Failed to start tunnel agent. Error: {cloudflared_agent_state.get('last_action_status', 'Unknown error')}", "error")
    time.sleep(1) # Brief pause to allow status update before redirect
    return redirect(url_for('status_page'))


@app.route('/stop', methods=['POST'])
def stop_tunnel():
    """Flask route to handle stopping the agent via UI button."""
    logging.info("UI request received: Stop tunnel agent.")
    if stop_cloudflared_container():
        flash("Tunnel agent stopping process initiated.", "info")
    else:
        # stop_cloudflared_container already set last_action_status with error details
        flash(f"Failed to stop tunnel agent. Error: {cloudflared_agent_state.get('last_action_status', 'Unknown error')}", "error")
    time.sleep(1) # Brief pause
    return redirect(url_for('status_page'))


@app.route('/update_settings', methods=['POST'])
def update_settings():
    """Flask route to handle updating settings (e.g., grace period) via UI."""
    global GRACE_PERIOD_SECONDS # We need to modify the global variable
    logging.info("UI request received: Update settings.")
    action_success = False
    original_grace_period = GRACE_PERIOD_SECONDS # Store original value

    try:
        submitted_hours_str = request.form.get('grace_period_hours')
        if submitted_hours_str is None or submitted_hours_str == '':
            raise ValueError("Grace period value cannot be empty.")

        # Use float for conversion to allow decimals like 0.5 hours
        submitted_hours = float(submitted_hours_str)
        if submitted_hours < 0:
             raise ValueError("Grace period cannot be negative.")
        # Optional: Add a reasonable maximum? (e.g., 7 days = 168 hours)
        max_hours = 7 * 24
        if submitted_hours > max_hours:
            raise ValueError(f"Grace period cannot exceed {max_hours} hours.")

        # Convert valid hours to seconds (integer)
        new_grace_period_seconds = int(submitted_hours * 3600)

        # Check if the value actually changed
        if new_grace_period_seconds != original_grace_period:
            GRACE_PERIOD_SECONDS = new_grace_period_seconds
            logging.info(f"Grace period updated via UI to: {GRACE_PERIOD_SECONDS} seconds ({submitted_hours} hours)")
            # Persist the change immediately
            save_state() # Uses lock internally if needed for file IO
            flash(f"Settings updated: Grace Period set to {submitted_hours} hours.", "success")
            action_success = True
        else:
            flash(f"Grace Period already set to {submitted_hours} hours. No change made.", "info")
            action_success = True # No change is still a success in terms of form submission

    except ValueError as e:
        logging.error(f"Invalid settings submission from UI: {e}")
        flash(f"Error updating settings: Invalid value submitted ({e}).", "error")
    except Exception as e:
        logging.error(f"Unexpected error updating settings via UI: {e}", exc_info=True)
        flash(f"Error updating settings: An unexpected error occurred.", "error")

    # Update last action status (optional, can be noisy)
    # if action_success:
    #     cloudflared_agent_state["last_action_status"] = f"Settings updated via UI at {datetime.now(timezone.utc).isoformat()}"
    # else:
    #     cloudflared_agent_state["last_action_status"] = f"Settings update via UI failed at {datetime.now(timezone.utc).isoformat()}"

    return redirect(url_for('status_page'))


@app.route('/force_delete/<path:hostname>', methods=['POST'])
def force_delete_rule(hostname):
    """Flask route to immediately delete a managed rule and its DNS record."""
    # Using <path:hostname> allows slashes if needed, though unlikely for hostnames
    logging.info(f"UI request received: Force delete rule for hostname: {hostname}")
    rule_removed_from_state = False
    dns_delete_status = "skipped" # skipped, success, failed
    cf_update_status = "skipped" # skipped, success, failed
    zone_id_for_delete = None

    # Step 1: Get the Zone ID from state before potentially deleting the rule
    with state_lock:
        rule_details = managed_rules.get(hostname)
        if rule_details:
            zone_id_for_delete = rule_details.get("zone_id")
            if not zone_id_for_delete:
                # Rule exists but has no zone_id, try fallback
                logging.warning(f"Rule {hostname} found in state for force delete, but lacks zone_id. Falling back to default CF_ZONE_ID.")
                zone_id_for_delete = CF_ZONE_ID
        else:
            # Rule not found in state, maybe deleted by cleanup concurrently?
            logging.warning(f"Rule {hostname} not found in state during force delete request. Attempting DNS delete using default CF_ZONE_ID if set.")
            zone_id_for_delete = CF_ZONE_ID # Best effort

    # Step 2: Attempt DNS deletion immediately
    if zone_id_for_delete and tunnel_state.get("id"):
        logging.info(f"Force Delete: Attempting DNS record deletion for {hostname} in zone {zone_id_for_delete}")
        if delete_cloudflare_dns_record(zone_id_for_delete, hostname, tunnel_state["id"]):
            dns_delete_status = "success"
        else:
            dns_delete_status = "failed"
            logging.error(f"Force Delete: Failed DNS delete for {hostname} in zone {zone_id_for_delete}. Tunnel update will proceed.")
    elif not zone_id_for_delete:
        logging.error(f"Force Delete: Cannot attempt DNS deletion for {hostname}: Zone ID could not be determined (checked state and default).")
        dns_delete_status = "skipped (no zone id)"
    else: # Missing tunnel ID
        logging.error(f"Force Delete: Cannot attempt DNS deletion for {hostname}: Missing Tunnel ID.")
        dns_delete_status = "skipped (no tunnel id)"

    # Step 3: Remove rule from local state
    with state_lock:
        if hostname in managed_rules:
            logging.info(f"Force Delete: Removing rule for {hostname} from local state.")
            del managed_rules[hostname]
            rule_removed_from_state = True
            save_state() # Persist the removal
        else:
            logging.warning(f"Force Delete: Rule '{hostname}' was already removed from state when processing request.")
            rule_removed_from_state = True # Still proceed with CF update if needed

    # Step 4: Trigger Cloudflare tunnel config update if state was modified
    if rule_removed_from_state:
        logging.info(f"Force Delete: Triggering Cloudflare tunnel config update after removing {hostname} from state.")
        if update_cloudflare_config():
            cf_update_status = "success"
            logging.info(f"Force Delete: Cloudflare tunnel config update successful after removing {hostname}.")
        else:
            cf_update_status = "failed"
            # update_cloudflare_config logs the error details
            logging.error(f"Force Delete: CRITICAL! State updated (rule removed), DNS delete status: {dns_delete_status}, but Cloudflare tunnel config update FAILED! Manual reconciliation might be needed.")

    # Step 5: Provide consolidated feedback via flash message
    if rule_removed_from_state:
        if cf_update_status == "success":
            msg = f"Successfully force-deleted rule for '{hostname}'. DNS: {dns_delete_status}."
            flash_category = "success" if dns_delete_status == "success" else "warning"
            flash(msg, flash_category)
        elif cf_update_status == "failed":
             msg = f"Error: Removed '{hostname}' from state (DNS: {dns_delete_status}), but FAILED Cloudflare tunnel config update! Reconciliation needed."
             flash(msg, "error")
        else: # Should not happen if rule_removed_from_state is True
             flash(f"Force delete for '{hostname}' processed state removal, but CF update was skipped?", "warning")
    else:
        # Rule wasn't in state to begin with
        flash(f"Rule '{hostname}' not found in managed state. No action taken.", "warning")

    # Update last action status for non-UI monitoring
    cloudflared_agent_state["last_action_status"] = f"Force delete '{hostname}': StateRemoved={rule_removed_from_state}, DNS={dns_delete_status}, CFUpdate={cf_update_status}"

    time.sleep(0.5) # Short delay before redirect
    return redirect(url_for('status_page'))


# --- Background Task Runner ---
def run_background_tasks():
    """Starts the Docker event listener and cleanup task threads."""
    if not docker_client:
        logging.warning("Docker client unavailable. Background tasks (event listener, cleanup) will not start.")
        return None, None

    if not tunnel_state.get("id"):
        logging.warning("Tunnel not fully initialized (missing ID). Background tasks will not start.")
        return None, None

    logging.info("Starting background threads (Docker Listener, Rule Cleanup)...")
    event_thread = threading.Thread(target=docker_event_listener, name="DockerEventListener", daemon=True)
    cleanup_thread = threading.Thread(target=cleanup_expired_rules, name="CleanupTask", daemon=True)

    event_thread.start()
    cleanup_thread.start()
    logging.info("Background threads started.")
    return event_thread, cleanup_thread

# --- Main Execution ---
if __name__ == '__main__':
    start_time = time.time()
    logging.info("-" * 60)
    logging.info("--- Cloudflare Tunnel Ingress Manager Starting Up ---")
    logging.info(f"--- Timestamp: {datetime.now().isoformat()} ---")
    logging.info("-" * 60)

    # Load initial state from file
    load_state()
    logging.info(f"Initial state loading complete. Grace period: {GRACE_PERIOD_SECONDS}s.")

    # Initialize background thread handles
    event_thread = None
    cleanup_thread = None

    # --- Perform startup checks and initialization ---
    if not docker_client:
         # Docker client failed to connect during initial setup
         logging.error("Docker client unavailable at startup. Functionality will be severely limited.")
         # Set initial states for UI clarity
         tunnel_state["status_message"] = "Error: Docker Unavailable"
         tunnel_state["error"] = "Failed to connect to Docker daemon on startup."
         cloudflared_agent_state["container_status"] = "docker_unavailable"
         cloudflared_agent_state["last_action_status"] = "Docker connection failed at startup."
         # Skip further Docker-dependent initialization
         logging.warning("Skipping tunnel initialization, reconciliation, agent management, and background tasks due to Docker unavailability.")
    else:
         # --- Docker Available: Proceed with normal startup ---
         logging.info("Docker client connected.")

         # Network check is deferred to start_cloudflared_container only if needed
         # logging.info(f"Docker network '{CLOUDFLARED_NETWORK_NAME}' will be checked/created when agent starts.")

         # Initialize Tunnel (Find/Create via API)
         initialize_tunnel()
         logging.info(f"Tunnel initialization attempt complete. Status: {tunnel_state.get('status_message')}")

         # Proceed only if tunnel initialization was successful (ID and Token obtained)
         if tunnel_state.get("id") and tunnel_state.get("token"):
             logging.info("Tunnel initialized successfully. Proceeding with reconciliation & agent checks.")

             # Run initial state reconciliation
             reconcile_state()
             logging.info("Initial state reconciliation complete.")

             # Check agent container status and attempt auto-start if needed
             logging.info("Checking cloudflared agent container status...")
             update_cloudflared_container_status() # Get current status
             if cloudflared_agent_state.get("container_status") != 'running':
                 # Don't try to start if Docker became unavailable *after* the initial check
                 if docker_client:
                     logging.info("Agent container is not running. Attempting auto-start...")
                     start_cloudflared_container()
                 else:
                      logging.warning("Agent container is not running, but Docker client became unavailable. Cannot auto-start.")
             else:
                 logging.info(f"Agent container '{CLOUDFLARED_CONTAINER_NAME}' is already running.")

             # Start background tasks only if Docker is still available
             if docker_client:
                 event_thread, cleanup_thread = run_background_tasks()
             else:
                  logging.warning("Docker client became unavailable after initial checks. Background tasks will not start.")

         else:
             # Tunnel initialization failed
             logging.error("Tunnel initialization failed (missing ID or Token). Cannot proceed with reconciliation, agent management, or background tasks.")
             # Ensure status message reflects the failure if no specific error was set
             if not tunnel_state.get("error"):
                 tunnel_state["status_message"] = "Tunnel Setup Failed (Missing ID/Token)"


    # --- Start Flask Web Server ---
    logging.info("Starting Flask web server...")
    flask_server_thread = None
    try:
        # Use Waitress, a production-grade WSGI server
        from waitress import serve
        # Run waitress in a separate thread so the main thread can monitor other tasks
        flask_server_thread = threading.Thread(
            target=serve,
            args=(app,),
            # Serve on all interfaces, disable noisy waitress logs by default
            kwargs={'host': '0.0.0.0', 'port': 5000, '_quiet': True},
            daemon=True, # Set as daemon so it exits if main thread exits
            name="FlaskWaitressServer"
        )
        flask_server_thread.start()
        startup_duration = time.time() - start_time
        logging.info(f"Flask server started using Waitress on 0.0.0.0:5000 (Startup time: {startup_duration:.2f}s)")

        # --- Main Monitoring Loop ---
        # Keep the main thread alive to monitor background threads and handle shutdown signals
        while True:
             all_threads_alive = True
             # Check Flask server thread
             if flask_server_thread and not flask_server_thread.is_alive():
                 logging.error("Flask web server thread unexpectedly terminated.")
                 all_threads_alive = False

             # Check Docker event listener thread (only if it was started)
             if event_thread and not event_thread.is_alive():
                 # Listener might stop if Docker connection fails repeatedly - this might be recoverable
                 logging.warning("Docker event listener thread terminated.")
                 # Consider attempting to restart it here? For now, just log.
                 # event_thread = None # Mark as stopped

             # Check cleanup thread (only if it was started)
             if cleanup_thread and not cleanup_thread.is_alive():
                 logging.error("Rule cleanup thread unexpectedly terminated.")
                 all_threads_alive = False # Treat cleanup thread termination as critical

             # If a critical thread died, initiate shutdown
             if not all_threads_alive:
                 logging.error("A critical background thread terminated. Initiating shutdown.")
                 stop_event.set() # Signal other threads to stop
                 break # Exit monitoring loop

             # Check if external shutdown signal received
             if stop_event.is_set():
                 logging.info("Shutdown signal received by main thread. Exiting monitoring loop.")
                 break

             # Sleep for a while before checking again
             time.sleep(10) # Check thread status every 10 seconds

    except ImportError:
        logging.warning("Waitress not found (run 'pip install waitress'). Using Flask's built-in development server (NOT recommended for production).")
        # Flask's dev server runs in the main thread and blocks here. Good for simple testing.
        try:
            # Turn off reloader if running in Docker usually
            app.run(host='0.0.0.0', port=5000, use_reloader=False)
        except KeyboardInterrupt:
            logging.info("Flask development server interrupted.")
        # No need for the monitoring loop if using dev server

    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received by main thread. Initiating shutdown.")
        stop_event.set()

    except Exception as server_err:
        logging.error(f"Web server failed to start or encountered a fatal error: {server_err}", exc_info=True)
        stop_event.set() # Signal shutdown on server error

    finally:
        # --- Shutdown Sequence ---
        logging.info("Shutdown sequence initiated...")
        stop_event.set() # Ensure stop signal is set for all threads

        # Optional: Wait briefly for threads to attempt graceful exit
        # (depends on how threads handle the stop_event)
        logging.info("Waiting briefly for background threads to stop...")
        time.sleep(2)

        # Log final status before exiting
        final_tunnel_status = tunnel_state.get('status_message', 'Unknown')
        final_agent_status = cloudflared_agent_state.get('container_status', 'Unknown')
        logging.info(f"Final Status: Tunnel='{final_tunnel_status}', Agent='{final_agent_status}'")

        logging.info("-" * 60)
        logging.info("--- Cloudflare Tunnel Ingress Manager Shutting Down ---")
        logging.info(f"--- Timestamp: {datetime.now().isoformat()} ---")
        logging.info("-" * 60)

        # Determine exit code based on critical errors during runtime
        exit_code = 0
        if tunnel_state.get("error"):
             logging.error(f"Exiting with code 1 due to persistent tunnel error: {tunnel_state['error']}")
             exit_code = 1
        elif cloudflared_agent_state.get("container_status") == "docker_unavailable":
             logging.error("Exiting with code 1 due to Docker unavailability.")
             exit_code = 1
        # Add checks for terminated critical threads if needed

        sys.exit(exit_code)