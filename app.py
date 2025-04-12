import os
import subprocess
import sys
import logging
import re
import docker # Import Docker SDK
from docker.errors import NotFound, APIError
from flask import Flask, jsonify, render_template_string, redirect, url_for, request
from dotenv import load_dotenv
import time # For potential waits

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
load_dotenv() # Load environment variables from .env file

CF_API_TOKEN = os.getenv('CF_API_TOKEN')
TUNNEL_NAME = os.getenv('TUNNEL_NAME')
# Name for the separate cloudflared container we will manage
CLOUDFLARED_CONTAINER_NAME = os.getenv('CLOUDFLARED_CONTAINER_NAME', f"cloudflared-agent-{TUNNEL_NAME}")
# Cloudflared Docker image
CLOUDFLARED_IMAGE = "cloudflare/cloudflared:latest"

if not CF_API_TOKEN:
    logging.error("FATAL: CF_API_TOKEN environment variable not set.")
    sys.exit(1)
if not TUNNEL_NAME:
    logging.error("FATAL: TUNNEL_NAME environment variable not set.")
    sys.exit(1)

# --- Docker Client ---
try:
    docker_client = docker.from_env()
    docker_client.ping() # Check connection
    logging.info("Successfully connected to Docker daemon.")
except Exception as e:
    logging.error(f"FATAL: Failed to connect to Docker daemon: {e}")
    logging.error("Ensure Docker is running and the socket is mounted correctly if applicable.")
    docker_client = None


# --- Global State ---
tunnel_state = {
    "name": TUNNEL_NAME,
    "id": None,
    "token": None,
    "status_message": "Initializing...",
    "error": None,
    "cloudflared_container_status": "unknown", # e.g., running, exited, not_found
    "last_action_status": None, # Feedback after start/stop
}

# --- Cloudflared Helper ---
def run_cloudflared_command(command_args):
    """Runs a cloudflared command and returns its output."""
    command = ['cloudflared'] + command_args
    env = os.environ.copy()
    env['CF_API_TOKEN'] = CF_API_TOKEN # Ensure token is in environment
    env['NONINTERACTIVE'] = '1'      # Try to prevent interactive prompts

    # Ensure TUNNEL_ORIGIN_CERT is NOT explicitly set here, rely on CF_API_TOKEN

    logging.info(f"Running command: {' '.join(command)}")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            env=env, # Pass the modified environment
            timeout=60
        )
        logging.info(f"Command successful. stdout:\n{result.stdout}")
        if result.stderr:
             logging.warning(f"Command stderr:\n{result.stderr}")
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {' '.join(command)}")
        logging.error(f"Return code: {e.returncode}")
        logging.error(f"stdout:\n{e.stdout}")
        logging.error(f"stderr:\n{e.stderr}")
        # Store the stderr in state if it seems relevant
        if "origin cert" in e.stderr.lower() or "tunnel" in e.stderr.lower() or "failed" in e.stderr.lower():
             # Prevent overwriting if a more specific error (like Docker API) is already set
            if "Docker API error" not in str(tunnel_state.get("error","")):
                tunnel_state["error"] = f"Cloudflared Error: {e.stderr.strip()}"
        raise # Re-raise the exception to be caught by the caller
    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: {' '.join(command)}")
        raise
    except Exception as e:
        logging.error(f"Error running command {' '.join(command)}: {e}")
        raise

# --- Tunnel Management Logic ---
def find_tunnel_id(name):
    """Finds the tunnel ID by its name."""
    try:
        stdout, _ = run_cloudflared_command(['tunnel', 'list'])
        # Example output line:
        # ID                                   NAME                CREATED              CONNECTIONS
        # c1a4e7a1-9a2a-4f6b-8c1b-1b8a0e2a4b9e my-automated-tunnel 2023-10-26T15:00:00Z 2xLAX, 1xDEN
        lines = stdout.splitlines()
        for line in lines[1:]: # Skip header
            parts = line.split()
            if len(parts) >= 2:
                 if parts[1] == name: # Check the second column specifically for the name
                     tunnel_id = parts[0]
                     logging.info(f"Found existing tunnel '{name}' with ID: {tunnel_id}")
                     return tunnel_id
    except Exception as e:
        # Avoid overwriting specific cloudflared errors unless it's a different exception
        if "Cloudflared Error" not in str(tunnel_state.get("error")):
             logging.error(f"Failed to list tunnels: {e}")
             tunnel_state["error"] = f"Failed to list tunnels: {e}"
        # If the error IS a cloudflared error, it's already set in run_cloudflared_command
    return None

def create_tunnel(name):
    """Creates a new tunnel."""
    try:
        stdout, _ = run_cloudflared_command(['tunnel', 'create', name])
        # Example output:
        # Created tunnel my-automated-tunnel with id c1a4e7a1-9a2a-4f6b-8c1b-1b8a0e2a4b9e
        match = re.search(r'tunnel\s+.*\s+with id\s+([a-f0-9-]+)', stdout, re.IGNORECASE)
        if match:
            tunnel_id = match.group(1)
            logging.info(f"Successfully created tunnel '{name}' with ID: {tunnel_id}")
            return tunnel_id
        else:
             logging.error(f"Could not parse tunnel ID from creation output: {stdout}")
             # Don't overwrite existing error if it's more specific
             if not tunnel_state.get("error"):
                 tunnel_state["error"] = "Could not parse tunnel ID from creation output."
             return None
    except Exception as e:
         # Avoid overwriting specific cloudflared errors
        if "Cloudflared Error" not in str(tunnel_state.get("error", "")):
            logging.error(f"Failed to create tunnel '{name}': {e}")
            tunnel_state["error"] = f"Failed to create tunnel: {e}"
        # If the error IS a cloudflared error, it's already set in run_cloudflared_command
        return None

def get_tunnel_token(tunnel_identifier):
    """Gets the token for a given tunnel ID or name."""
    try:
        # Token command works with ID or name
        token, _ = run_cloudflared_command(['tunnel', 'token', tunnel_identifier])
        logging.info(f"Successfully retrieved token for tunnel: {tunnel_identifier}")
        return token
    except Exception as e:
        # Avoid overwriting specific cloudflared errors
        if "Cloudflared Error" not in str(tunnel_state.get("error", "")):
            logging.error(f"Failed to get token for tunnel '{tunnel_identifier}': {e}")
            tunnel_state["error"] = f"Failed to get token: {e}"
        # If the error IS a cloudflared error, it's already set in run_cloudflared_command
        return None

def initialize_tunnel():
    """Checks for the tunnel, creates if needed, and gets the token."""
    tunnel_state["status_message"] = f"Checking for tunnel '{TUNNEL_NAME}'..."
    tunnel_state["error"] = None # Clear previous errors at start of initialization
    tunnel_id = None
    try:
        tunnel_id = find_tunnel_id(TUNNEL_NAME)
        # If find_tunnel_id failed due to cloudflared error, state['error'] will be set
    except Exception as e:
        # Catch other unexpected errors during find_tunnel_id call
        logging.error(f"Unexpected error during find_tunnel_id: {e}", exc_info=True)
        if not tunnel_state.get("error"): # Set general error if cloudflared didn't set one
            tunnel_state["error"] = f"Failed to check tunnels: {e}"
        tunnel_state["status_message"] = "Failed during tunnel check."
        return # Stop if listing failed

    # Proceed only if listing didn't explicitly fail
    if not tunnel_id and not tunnel_state.get("error"):
        tunnel_state["status_message"] = f"Tunnel '{TUNNEL_NAME}' not found. Creating..."
        try:
            tunnel_id = create_tunnel(TUNNEL_NAME)
            # If create_tunnel failed due to cloudflared error, state['error'] will be set
        except Exception as e:
            # Catch other unexpected errors during create_tunnel call
            logging.error(f"Unexpected error during create_tunnel: {e}", exc_info=True)
            if not tunnel_state.get("error"): # Set general error if cloudflared didn't set one
                tunnel_state["error"] = f"Failed to create tunnel: {e}"
            tunnel_state["status_message"] = "Failed during tunnel creation."
            return # Stop if creation failed

        if not tunnel_id:
            # If create_tunnel returned None but didn't raise Exception
            # state['error'] should have been set by run_cloudflared_command if it failed
            if tunnel_state.get("error"):
                 tunnel_state["status_message"] = "Failed to create tunnel (see error details)."
            else:
                 tunnel_state["status_message"] = "Failed to create tunnel (no specific error)."
            return # Stop if creation failed

    # Proceed only if we have an ID and no critical error occurred
    if tunnel_id:
        tunnel_state["id"] = tunnel_id
        tunnel_state["status_message"] = f"Fetching token for tunnel ID {tunnel_id}..."
        token = None
        try:
            token = get_tunnel_token(tunnel_id)
            # If get_tunnel_token failed due to cloudflared error, state['error'] will be set
        except Exception as e:
            # Catch other unexpected errors during get_tunnel_token call
            logging.error(f"Unexpected error during get_tunnel_token: {e}", exc_info=True)
            if not tunnel_state.get("error"): # Set general error if cloudflared didn't set one
                 tunnel_state["error"] = f"Failed to retrieve token: {e}"
            tunnel_state["status_message"] = "Failed during token retrieval."
            return # Stop if token retrieval failed

        if token:
            tunnel_state["token"] = token
            tunnel_state["status_message"] = "Tunnel setup complete."
            tunnel_state["error"] = None # Clear errors if we reached success
        else:
            # If get_tunnel_token returned None but didn't raise Exception
             if tunnel_state.get("error"):
                 tunnel_state["status_message"] = "Failed to retrieve tunnel token (see error details)."
             else:
                 tunnel_state["status_message"] = "Failed to retrieve tunnel token (no specific error)."
    elif not tunnel_state.get("error"):
         # This state should ideally not be reached if logic is correct
         tunnel_state["status_message"] = "Tunnel initialization incomplete."
         tunnel_state["error"] = "Tunnel ID was not found or created, but no specific error was recorded."


# --- Docker Container Management ---
# (This section remains unchanged from the previous complete version)
def get_cloudflared_container():
    """Gets the cloudflared container object if it exists."""
    if not docker_client:
        logging.warning("Docker client not available.")
        return None
    try:
        container = docker_client.containers.get(CLOUDFLARED_CONTAINER_NAME)
        return container
    except NotFound:
        return None
    except APIError as e:
        logging.error(f"Docker API error getting container: {e}")
        tunnel_state["error"] = f"Docker API error: {e}" # Overwrite general errors with specific Docker errors
        return None

def update_cloudflared_container_status():
    """Updates the tunnel_state with the current container status."""
    if not docker_client:
        tunnel_state["cloudflared_container_status"] = "docker_unavailable"
        return
    container = get_cloudflared_container()
    if container:
        try:
            # Reload attributes to get the latest status
            container.reload()
            tunnel_state["cloudflared_container_status"] = container.status
        except (NotFound, APIError) as e:
            logging.warning(f"Error reloading container status: {e}")
            # If we can't reload, assume not found for safety
            tunnel_state["cloudflared_container_status"] = "not_found"

    else:
        # Check if the error state already indicates a Docker problem
        if "Docker API error" not in str(tunnel_state.get("error", "")):
             tunnel_state["cloudflared_container_status"] = "not_found"
        else:
             tunnel_state["cloudflared_container_status"] = "docker_error"


def start_cloudflared_container():
    """Starts the cloudflared agent container."""
    tunnel_state["last_action_status"] = None # Clear previous action status
    if not docker_client:
        msg = "Docker client not available. Cannot start container."
        logging.error(msg)
        tunnel_state["last_action_status"] = f"Error: {msg}"
        return False
    if not tunnel_state.get("token"):
        msg = "Tunnel token not available. Cannot start container."
        logging.error(msg)
        tunnel_state["last_action_status"] = f"Error: {msg}"
        # Attempt to re-initialize tunnel to get token if possible
        if not tunnel_state.get("id"):
             initialize_tunnel() # Try to get ID and token again
             if not tunnel_state.get("token"): # Check again after re-init
                 return False
        else: # ID exists but no token, likely init failed
             # Maybe try getting token again?
             token_retry = get_tunnel_token(tunnel_state.get("id"))
             if token_retry:
                 tunnel_state["token"] = token_retry
             else:
                 msg = "Tunnel token not available (retrieval failed previously). Cannot start container."
                 logging.error(msg)
                 tunnel_state["last_action_status"] = f"Error: {msg}"
                 return False


    token = tunnel_state["token"]
    container = get_cloudflared_container()

    try:
        if container:
            if container.status == 'running':
                msg = f"Container '{CLOUDFLARED_CONTAINER_NAME}' is already running."
                logging.info(msg)
                tunnel_state["last_action_status"] = msg
                return True
            else:
                logging.info(f"Starting existing container '{CLOUDFLARED_CONTAINER_NAME}'...")
                container.start()
                tunnel_state["last_action_status"] = f"Successfully started container '{CLOUDFLARED_CONTAINER_NAME}'."
                logging.info(tunnel_state["last_action_status"])
                time.sleep(2)
                update_cloudflared_container_status()
                return True
        else:
            logging.info(f"Container '{CLOUDFLARED_CONTAINER_NAME}' not found. Creating and starting...")
            try:
                logging.info(f"Pulling image {CLOUDFLARED_IMAGE}...")
                docker_client.images.pull(CLOUDFLARED_IMAGE)
            except APIError as img_err:
                 logging.warning(f"Could not pull image {CLOUDFLARED_IMAGE}: {img_err}. Proceeding with local version if available.")

            new_container = docker_client.containers.run(
                image=CLOUDFLARED_IMAGE,
                command=f"tunnel --no-autoupdate run --token {token}",
                name=CLOUDFLARED_CONTAINER_NAME,
                network_mode="host", # Ensure this matches your setup needs
                restart_policy={"Name": "unless-stopped"},
                detach=True,
                remove=False # Keep container unless explicitly removed
            )
            tunnel_state["last_action_status"] = f"Successfully created and started container '{new_container.name}'."
            logging.info(tunnel_state["last_action_status"])
            time.sleep(2)
            update_cloudflared_container_status()
            return True
    except APIError as e:
        msg = f"Docker API error starting container: {e}"
        logging.error(msg)
        tunnel_state["last_action_status"] = f"Error: {msg}"
        update_cloudflared_container_status()
        return False
    except Exception as e:
        msg = f"Unexpected error starting container: {e}"
        logging.error(msg, exc_info=True)
        tunnel_state["last_action_status"] = f"Error: {msg}"
        update_cloudflared_container_status()
        return False


def stop_cloudflared_container():
    """Stops the cloudflared agent container."""
    tunnel_state["last_action_status"] = None
    if not docker_client:
        msg = "Docker client not available. Cannot stop container."
        logging.error(msg)
        tunnel_state["last_action_status"] = f"Error: {msg}"
        return False

    container = get_cloudflared_container()

    if not container:
        msg = f"Container '{CLOUDFLARED_CONTAINER_NAME}' not found. Cannot stop."
        logging.warning(msg)
        tunnel_state["last_action_status"] = msg
        update_cloudflared_container_status()
        return True # Considered successful as it's not running

    if container.status != 'running':
        msg = f"Container '{CLOUDFLARED_CONTAINER_NAME}' is not running (status: {container.status})."
        logging.info(msg)
        tunnel_state["last_action_status"] = msg
        # If exited, maybe try removing it?
        # if container.status == 'exited':
        #     try:
        #         logging.info(f"Removing exited container '{CLOUDFLARED_CONTAINER_NAME}'...")
        #         container.remove()
        #         tunnel_state["last_action_status"] += " Container removed."
        #     except APIError as rm_err:
        #         logging.warning(f"Could not remove exited container: {rm_err}")
        update_cloudflared_container_status()
        return True

    try:
        logging.info(f"Stopping container '{CLOUDFLARED_CONTAINER_NAME}'...")
        container.stop(timeout=30)
        tunnel_state["last_action_status"] = f"Successfully stopped container '{CLOUDFLARED_CONTAINER_NAME}'."
        logging.info(tunnel_state["last_action_status"])
        # Optional: remove the container after stopping
        # logging.info(f"Removing stopped container '{CLOUDFLARED_CONTAINER_NAME}'...")
        # container.remove()
        # tunnel_state["last_action_status"] += " Container removed."
        time.sleep(2)
        update_cloudflared_container_status()
        return True
    except APIError as e:
        msg = f"Docker API error stopping container: {e}"
        logging.error(msg)
        tunnel_state["last_action_status"] = f"Error: {msg}"
        update_cloudflared_container_status()
        return False
    except Exception as e:
        msg = f"Unexpected error stopping container: {e}"
        logging.error(msg, exc_info=True)
        tunnel_state["last_action_status"] = f"Error: {msg}"
        update_cloudflared_container_status()
        return False

# --- Flask Web Server ---
app = Flask(__name__)
app.secret_key = os.urandom(24) # Needed for flash messages if we add them

@app.route('/')
def status_page():
    """Displays the current tunnel status and controls."""
    # Update container status before rendering
    update_cloudflared_container_status()

    # Mask token for display purposes
    display_token = "Not available"
    if tunnel_state.get("token"):
        token = tunnel_state["token"]
        if len(token) > 10:
            display_token = f"{token[:5]}...{token[-5:]}"
        else:
            display_token = "Token retrieved (short)"
    elif tunnel_state.get("error") and "token" in tunnel_state["error"].lower():
         display_token = "Failed to retrieve token"
    elif tunnel_state.get("id"):
        display_token = "Token not retrieved"

    # Determine overall error state for display class
    display_error = tunnel_state.get("error") or (tunnel_state.get("last_action_status") and "Error" in tunnel_state["last_action_status"])

    # Simple HTML template as a string
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cloudflare Tunnel Status</title>
        <style>
            body { font-family: sans-serif; padding: 20px; background-color: #f4f4f4; color: #333; }
            h1, h2 { color: #555; }
            .container { background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
            .status-box { padding: 10px; border: 1px solid #ccc; border-radius: 5px; margin-top: 10px; word-wrap: break-word; }
            .error { background-color: #ffebeb; border-color: #ffc2c2; color: #a00; }
            .success { background-color: #e6ffed; border-color: #c3e6cb; color: #155724;}
            .info { background-color: #e7f3fe; border-color: #b8daff; color: #004085;}
            .warning { background-color: #fff3cd; border-color: #ffeeba; color: #856404;}
            pre { background-color: #eee; padding: 10px; border-radius: 3px; word-wrap: break-word; white-space: pre-wrap;}
            .button { padding: 10px 15px; border: none; border-radius: 4px; color: white; cursor: pointer; font-size: 1em; margin-right: 10px; }
            .start-button { background-color: #28a745; } /* Green */
            .stop-button { background-color: #dc3545; } /* Red */
            .button:disabled { background-color: #cccccc; cursor: not-allowed; opacity: 0.6; }
            form { display: inline-block; }
        </style>
    </head>
    <body>
        <h1>Cloudflare Tunnel Manager</h1>

        <div class="container">
            <h2>Initialization Status</h2>
            <div class="status-box {{ 'error' if error else ('success' if token else 'info') }}">
                <p><strong>Message:</strong> {{ status_message }}</p>
                {% if error %}
                <p><strong>Error Details:</strong> <pre>{{ error }}</pre></p>
                {% endif %}
            </div>
            <h3>Tunnel Details</h3>
            <p><strong>Desired Tunnel Name:</strong> <pre>{{ name }}</pre></p>
            <p><strong>Tunnel ID:</strong> <pre>{{ id if id else 'Not available' }}</pre></p>
            <p><strong>Tunnel Token:</strong> <pre>{{ display_token }}</pre></p>
             <p><small>Note: Full token must be available internally to start the tunnel agent.</small></p>
        </div>

        <div class="container">
             <h2>Tunnel Agent Control (<pre>{{ cloudflared_container_name }}</pre>)</h2>
             <p><strong>Agent Container Status:</strong>
                <strong style="text-transform: capitalize;"
                        class="{{ 'success' if cloudflared_container_status == 'running' else ('error' if 'error' in cloudflared_container_status or 'unavailable' in cloudflared_container_status or cloudflared_container_status == 'dead' else ('warning' if cloudflared_container_status == 'exited' else 'info')) }}">
                  {{ cloudflared_container_status.replace('_', ' ') }}
                </strong>
             </p>

             {% if last_action_status %}
             <div class="status-box {{ 'error' if 'Error' in last_action_status else 'info' }}">
                <strong>Last Action Result:</strong> {{ last_action_status }}
             </div>
             {% endif %}

             <form action="{{ url_for('start_tunnel') }}" method="post" style="margin-right: 10px;">
                <button type="submit" class="button start-button"
                        {{ 'disabled' if not token or cloudflared_container_status == 'running' or not docker_client }}>
                    Start Tunnel Agent
                </button>
             </form>
             <form action="{{ url_for('stop_tunnel') }}" method="post">
                <button type="submit" class="button stop-button"
                        {{ 'disabled' if cloudflared_container_status != 'running' or not docker_client }}>
                    Stop Tunnel Agent
                </button>
             </form>
             <p><small>Agent control requires connection to Docker daemon.</small></p>
        </div>

    </body>
    </html>
    """
    return render_template_string(
        html_template,
        # Tunnel details
        name=tunnel_state["name"],
        id=tunnel_state.get("id"),
        status_message=tunnel_state["status_message"],
        error=tunnel_state.get("error"),
        display_token=display_token,
        token=tunnel_state.get("token"), # Pass raw token for button logic
        # Agent details
        cloudflared_container_name=CLOUDFLARED_CONTAINER_NAME,
        cloudflared_container_status=tunnel_state["cloudflared_container_status"],
        last_action_status=tunnel_state.get("last_action_status"),
        # Other state
        docker_client=docker_client # Pass docker client availability to template
    )

# --- Action Routes ---

@app.route('/start', methods=['POST'])
def start_tunnel():
    """Endpoint to trigger starting the tunnel."""
    logging.info("Received request to start tunnel agent.")
    start_cloudflared_container()
    # Redirect back to the status page to show the result
    return redirect(url_for('status_page'))

@app.route('/stop', methods=['POST'])
def stop_tunnel():
    """Endpoint to trigger stopping the tunnel."""
    logging.info("Received request to stop tunnel agent.")
    stop_cloudflared_container()
    # Redirect back to the status page
    return redirect(url_for('status_page'))


# --- Main Execution ---
if __name__ == '__main__':
    # Initialize tunnel on startup
    try:
         initialize_tunnel()
    except Exception as init_err:
         logging.error(f"Unexpected error during initial tunnel setup: {init_err}", exc_info=True)
         if not tunnel_state.get("error"):
             tunnel_state["error"] = f"Initialization failed: {init_err}"
         tunnel_state["status_message"] = "Tunnel initialization failed."

    # Ensure initial container status is known if Docker client is available
    if docker_client:
        try:
            update_cloudflared_container_status()
        except Exception as docker_err:
            logging.error(f"Error getting initial Docker status: {docker_err}", exc_info=True)
            tunnel_state["cloudflared_container_status"] = "docker_error"


    # Run Flask app
    logging.info("Starting Flask application server.")
    app.run(host='0.0.0.0', port=5000)