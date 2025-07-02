#!/usr/bin/env python3

## Script name: creators_v1.0.py
##
## Purpose: Authenticates with the Nobl9 Admin API and retrieves ownership metadata (CreatedBy, CreatedAt, UpdatedAt)
## for SLOs and Projects, then displays and exports the information in a human-readable format.
##
## Dependencies: sloctl, pandas, openpyxl, requests, toml
## Compatible with: macOS and Linux
##
## Author: Jeremy Cooper
## Date Created: 2025-05-15

import subprocess
import json
import base64
import os
import csv
import sys
import shutil
import requests 
from datetime import datetime

def check_dependencies():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append("requests")
    try:
        import pandas
    except ImportError:
        missing.append("pandas")
    try:
        import openpyxl
    except ImportError:
        missing.append("openpyxl")
    try:
        import importlib.util
        if importlib.util.find_spec("toml") is None:
            missing.append("toml")
    except Exception:
        missing.append("toml")

    if not shutil.which("sloctl"):
        print("ERROR: 'sloctl' is not installed or not in PATH.")
        print("You can install it from https://docs.nobl9.com/sloctl/")
        sys.exit(1)

    if missing:
        print("\nMissing required Python packages:")
        for pkg in missing:
            note = " (required for Excel export)" if pkg == "openpyxl" else ""
            print(f"  - {pkg}{note}")
        print("\nYou can install them using:")
        print("  pip3 install " + " ".join(missing))
        print("\nIf you're using a virtual environment, make sure it is activated.")
        sys.exit(1)

def load_contexts_from_toml():
    import toml

    default_toml_path = os.path.expanduser("~/.config/nobl9/config.toml")

    if not os.path.isfile(default_toml_path):
        print("TOML config file not found at expected path:")
        print(f"  {default_toml_path}")
        user_path = input("\nPlease provide the full path to your Nobl9 config.toml file: ").strip()
        if not os.path.isfile(user_path):
            print(f"ERROR: Could not find TOML file at {user_path}")
            return {}
        print("\nTo avoid this prompt in the future, update the default path inside the 'load_contexts_from_toml()' function.\n")
        toml_path = user_path
    else:
        toml_path = default_toml_path

    try:
        toml_data = toml.load(toml_path)
        raw_contexts = toml_data.get("contexts", {})
        parsed_contexts = {}
        for ctx_name, creds in raw_contexts.items():
            if "clientId" in creds and "clientSecret" in creds:
                parsed_contexts[ctx_name] = {
                    "clientId": creds["clientId"],
                    "clientSecret": creds["clientSecret"],
                    "accessToken": creds.get("accessToken", "")  # Add this line
                }
        return parsed_contexts
    except Exception as e:
        print(f"Failed to parse TOML config: {e}")
        return {}


def enhanced_choose_context():
    contexts_dict = load_contexts_from_toml()
    if not contexts_dict:
        print("No valid contexts found. Please ensure your config.toml is set up correctly.")
        return None, None
    context_names = list(contexts_dict.keys())
    if len(context_names) == 1:
        selected = context_names[0]
        result = subprocess.run(["sloctl", "config", "use-context", selected], 
                              capture_output=True, text=True, check=False)
        return selected, contexts_dict[selected]
    print("\nAvailable contexts:")
    for i, name in enumerate(context_names):
        print(f"  [{i + 1}] {name}")
    choice = input("Select a context: ").strip()
    try:
        index = int(choice) - 1
        selected = context_names[index]
        result = subprocess.run(["sloctl", "config", "use-context", selected], 
                              capture_output=True, text=True, check=False)
        return selected, contexts_dict[selected]
    except Exception:
        print("ERROR: Invalid context selection.")
        return None, None

def format_timestamp(iso_string):
    try:
        dt = datetime.strptime(iso_string, "%Y-%m-%dT%H:%M:%SZ")
        return dt.strftime("%m/%d/%y %H:%M")
    except Exception:
        return iso_string

def decode_jwt_payload(token):
    """Decode JWT token to extract organization info."""
    try:
        payload_b64 = token.split('.')[1]
        payload_b64 += '=' * (-len(payload_b64) % 4)
        payload_json = base64.b64decode(payload_b64).decode('utf-8')
        payload = json.loads(payload_json)
        return payload.get('m2mProfile', {}).get('organization', None)
    except Exception as e:
        return None

def authenticate(credentials):
    client_id = credentials["clientId"]
    client_secret = credentials["clientSecret"]
    
    # Extract org from existing token in TOML
    org_name = None
    if stored_token := credentials.get("accessToken"):
        org_name = decode_jwt_payload(stored_token)
        if org_name:
            print(f"Found organization from stored token: {org_name}")
    
    # Always get a fresh token
    encoded_creds = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded_creds}",
        "Content-Type": "application/json",
        "Organization": org_name or input("Enter Nobl9 Organization name: ")
    }
    response = requests.post("https://app.nobl9.com/api/accessToken", headers=headers)
    token = response.json().get("access_token")
    if not token:
        print("ERROR: Failed to get access token")
        exit(1)
    
    print(f"\nUsing organization: {headers['Organization']}")
    return token, headers["Organization"]

def run_sloctl(command):
    print("Retrieving data...", end="", flush=True)
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    print(" Done!")
    if result.returncode != 0:
        print(f"ERROR: Command failed:\n{result.stderr}")
        exit(1)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"ERROR: JSON parsing error: {e}")
        exit(1)

def collect_users(token, org):
    headers = {"Authorization": f"Bearer {token}", "Organization": org}
    base_url = "https://app.nobl9.com/api/usrmgmt/v2/users?limit=50"
    next_token = None
    seen_tokens = set()
    all_users = []
    page_count = 0

    while True:
        url = base_url
        if next_token:
            if next_token in seen_tokens:
                print("Repeated next token detected — stopping pagination.")
                break
            seen_tokens.add(next_token)
            url += f"&next={next_token}"

        try:
            res = requests.get(url, headers=headers, timeout=10)
        except requests.exceptions.Timeout:
            print("Request timed out.")
            break
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            break

        if not res.ok:
            print(f"API error {res.status_code}: {res.text}")
            break

        data = res.json()
        users = data.get("users", [])
        all_users.extend(users)

        next_token = data.get("paging", {}).get("next")
        page_count += 1
        print(f"Page {page_count}: Retrieved {len(users)} users (Total so far: {len(all_users)})")

        if not next_token:
            break

    print(f"Total users retrieved: {len(all_users)}")
    # Build a mapping: userId -> "First Last"
    user_map = {}
    for u in all_users:
        uid = u.get("userId")
        name = f"{u.get('firstName', '')} {u.get('lastName', '')}".strip()
        if uid:
            user_map[uid] = name
    return user_map


    while True:
        url = base_url
        if page_token:
            url += f"&pageToken={page_token}"
        res = requests.get(url, headers=headers)
        if not res.ok:
            break
        data = res.json()
        all_users.extend(data.get("users", []))
        page_token = data.get("paging", {}).get("next")
        if not page_token:
            break

    return all_users

def export_data(data, user_map, resource_type, context):
    import pandas as pd
    export_choice = input("\nWould you like to export the results? [1] CSV  [2] Excel  [Enter to skip]: ").strip()
    if export_choice not in {"1", "2"}:
        return

    rows = []
    for item in data:
        metadata = item.get("metadata", {})
        spec = item.get("spec", {})
        created_raw = spec.get("createdAt", "")
        row = {
            "displayName": metadata.get("displayName", ""),
            "name": metadata.get("name", ""),
            "project": metadata.get("project", "") if resource_type == "slo" else "",
            "createdAt": format_timestamp(created_raw),
            "createdBy": user_map.get(spec.get("createdBy", ""), spec.get("createdBy", ""))
        }

        if resource_type == "slo":
            updated_raw = item.get("status", {}).get("updatedAt", "")
            row["updatedAt"] = "" if created_raw == updated_raw else format_timestamp(updated_raw)

        rows.append(row)

    os.makedirs("exports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"exports/{context}_{resource_type}_{timestamp}"

    df = pd.DataFrame(rows)
    if export_choice == "1":
        df.to_csv(f"{filename}.csv", index=False)
        print(f"Exported to {filename}.csv")
    elif export_choice == "2":
        df.to_excel(f"{filename}.xlsx", index=False)
        print(f"Exported to {filename}.xlsx")

def display_slos(slos, user_map):
    print(f"\n{'SLO Display Name':50} {'Name':40} {'Project':20} {'Created At':25} {'Updated At':25} {'Created By'}")
    print("-" * 180)  # Increased total width
    for item in slos:
        metadata = item.get("metadata", {})
        spec = item.get("spec", {})
        display_name = metadata.get("displayName", "")
        name = metadata.get("name", "")
        project = metadata.get("project", "")
        created_raw = spec.get("createdAt", "")
        updated_raw = item.get("status", {}).get("updatedAt", "")
        created_at = format_timestamp(created_raw)
        updated_at = "" if created_raw == updated_raw else format_timestamp(updated_raw)
        created_by_id = spec.get("createdBy", "")
        created_by = user_map.get(created_by_id, created_by_id)
        print(f"{display_name[:50]:50} {name[:40]:40} {project[:20]:20} {created_at[:25]:25} {updated_at[:25]:25} {created_by}")

def display_projects(projects, user_map):
    print(f"\n{'Display Name':30} {'Name':25} {'Created At':25} {'Created By'}")
    print("-" * 110)
    for item in projects:
        metadata = item.get("metadata", {})
        spec = item.get("spec", {})
        display_name = metadata.get("displayName", "")
        name = metadata.get("name", "")
        created_raw = spec.get("createdAt", "")
        created_at = format_timestamp(created_raw)
        created_by_id = spec.get("createdBy", "")
        created_by = user_map.get(created_by_id, created_by_id)
        print(f"{display_name[:30]:30} {name[:25]:25} {created_at[:25]:25} {created_by}")

def main_loop():
    check_dependencies()
    context, credentials = enhanced_choose_context()
    token, org = authenticate(credentials)
    user_map = collect_users(token, org)

    while True:
        print("\nWhat do you want to view?")
        print("  [1] SLOs")
        print("  [2] Projects")
        print("  [x] Exit")
        choice = input("Select an option: ")

        if choice == "x":
            print("Exiting...")
            break

        cmd_map = {
            "1": "sloctl get slos -A -o json",
            "2": "sloctl get projects -o json"
        }

        if choice not in cmd_map:
            print("ERROR: Invalid selection.")
            continue

        data = run_sloctl(cmd_map[choice])
        if choice == "1":
            print(f"\nFound {len(data)} SLOs")
            display_slos(data, user_map)
            export_data(data, user_map, "slo", context)
        elif choice == "2":
            print(f"\nFound {len(data)} Projects")
            display_projects(data, user_map)
            export_data(data, user_map, "project", context)

if __name__ == "__main__":
    main_loop()
