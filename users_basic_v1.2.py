#!/usr/bin/env python3
"""
Script name: users_basic_v1.2.py

Purpose: Fetches basic user information from Nobl9 API and displays it in a simple table format.
Retrieves user names and IDs, then offers export options in CSV, JSON, or Excel formats.

Dependencies: toml, pandas, openpyxl, tabulate, requests
Compatible with: macOS and Linux

Author: Jeremy Cooper
Date Created: 2025-07-02
"""

import os
import csv
import base64
import json
import requests
import argparse
from datetime import datetime

def check_dependencies():
    missing = []
    for pkg in ["toml", "pandas", "openpyxl", "tabulate", "requests"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print("Missing required Python packages:")
        for pkg in missing:
            print(f"  - {pkg}")
        print("\nInstall them using:\n  pip3 install " + " ".join(missing))
        exit(1)

def load_contexts_from_toml():
    import toml
    default_path = os.path.expanduser("~/.config/nobl9/config.toml")
    if not os.path.isfile(default_path):
        print(f"TOML config not found at {default_path}")
        alt_path = input("Please enter full path to config.toml: ").strip()
        if not os.path.isfile(alt_path):
            print(f"ERROR: File not found: {alt_path}")
            exit(1)
        print("To avoid this prompt in the future, update the default_path in load_contexts_from_toml().")
        path = alt_path
    else:
        path = default_path

    toml_data = toml.load(path)
    return toml_data.get("contexts", {})

def choose_context(contexts, override=None):
    keys = list(contexts.keys())
    if not keys:
        print("No contexts found.")
        exit(1)
    if override:
        if override in keys:
            return override
        print(f"Context '{override}' not found in TOML.")
        exit(1)
    if len(keys) == 1:
        return keys[0]
    print("Available contexts:")
    for i, k in enumerate(keys):
        print(f"  [{i + 1}] {k}")
    choice = input("Select a context: ").strip()
    try:
        return keys[int(choice) - 1]
    except:
        print("Invalid selection.")
        exit(1)

def get_token(client_id, client_secret, org_name):
    creds = f"{client_id}:{client_secret}"
    b64_creds = base64.b64encode(creds.encode()).decode()
    headers = {
        "Authorization": f"Basic {b64_creds}",
        "Content-Type": "application/json",
        "Organization": org_name
    }
    res = requests.post("https://app.nobl9.com/api/accessToken", headers=headers)
    token = res.json().get("access_token")
    if not token:
        print("ERROR: Failed to get access token")
        print("Response:", res.text)
        exit(1)
    return token

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

def fetch_users(token, org):
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
    return all_users

def display_and_export(users, org, context, export_flag=None):
    import pandas as pd

    rows = []
    for u in users:
        name = f"{u.get('firstName', '')} {u.get('lastName', '')}".strip()
        userid = u.get("userId", "")
        rows.append({"Name": name, "UserID": userid})

    print("\nUser Table:")
    print("Name                    UserID")
    for row in rows:
        print(f"{row['Name']:<20} {row['UserID']}")

    if not export_flag:
        choice = input("\nExport results? [1] CSV  [2] JSON  [3] XLSX  [Enter to skip]: ").strip()
    else:
        choice = {'c': '1', 'j': '2', 'x': '3'}.get(export_flag.lower(), '')

    if not choice:
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    base = f"export_users_basic/users-{context}_{timestamp}"
    os.makedirs("export_users_basic", exist_ok=True)
    df = pd.DataFrame(rows)

    if choice == "1":
        df.to_csv(f"{base}.csv", index=False)
        print(f"Exported to {base}.csv")
    elif choice == "2":
        with open(f"{base}.json", "w") as f:
            json.dump(rows, f, indent=2)
        print(f"Exported to {base}.json")
    elif choice == "3":
        df.to_excel(f"{base}.xlsx", index=False)
        print(f"Exported to {base}.xlsx")
    else:
        print("Invalid option. Skipped export.")

def main():
    parser = argparse.ArgumentParser(description="Fetch Nobl9 users and export to file.")
    parser.add_argument("-c", action="store_true", help="Export as CSV")
    parser.add_argument("-j", action="store_true", help="Export as JSON")
    parser.add_argument("-x", action="store_true", help="Export as XLSX")
    parser.add_argument("--context", help="Specify context name")
    parser.add_argument("--org", help="Specify Nobl9 organization name")
    args = parser.parse_args()

    check_dependencies()
    contexts = load_contexts_from_toml()
    context = choose_context(contexts, override=args.context)
    creds = contexts[context]
    
    # Extract org from existing token in TOML
    org_name = None
    if stored_token := creds.get("accessToken"):
        org_name = decode_jwt_payload(stored_token)
        if org_name:
            print(f"Found organization from stored token: {org_name}")
    
    # Allow override from command line
    org_name = args.org or org_name or input("Enter Nobl9 Organization name: ").strip()
    
    # Always get a fresh token
    client_id = creds.get("clientId")
    client_secret = creds.get("clientSecret")
    if not client_id or not client_secret:
        print("Missing credentials in context.")
        exit(1)
    
    token = get_token(client_id, client_secret, org_name)
    print(f"\nUsing organization: {org_name}")

    users = fetch_users(token, org_name)

    export_flag = None
    if args.c:
        export_flag = "c"
    elif args.j:
        export_flag = "j"
    elif args.x:
        export_flag = "x"

    display_and_export(users, org_name, context, export_flag)

if __name__ == "__main__":
    main()
