#!/usr/bin/env python3
"""
Script name: audit_logs_for_admins_v1.0.py

Purpose: Fetches and analyzes audit logs for admin users in Nobl9. Retrieves detailed audit trail
information including timestamps, admin actions, and user activities. Supports filtering by time
periods and specific admin users, with export options in CSV, JSON, and Excel formats.

Dependencies: requests, pandas, openpyxl, toml, tabulate, sloctl CLI
Compatible with: macOS and Linux

Author: Jeremy Cooper
Date Created: 2025-07-02
"""

import requests
import sys
import json
import base64
import os
import toml
import shutil
import subprocess
from datetime import datetime, timedelta

# Ensure required Python modules and sloctl CLI are available
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
        import toml
    except ImportError:
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
        sys.exit(1)

# Decode JWT token to extract organization info
def decode_jwt_payload(token):
    try:
        # JWT has three parts: header.payload.signature
        payload_b64 = token.split('.')[1]
        # Add padding if necessary
        payload_b64 += '=' * (-len(payload_b64) % 4)
        payload_json = base64.b64decode(payload_b64).decode('utf-8')
        payload = json.loads(payload_json)
        # Look for organization in m2mProfile
        return payload.get('m2mProfile', {}).get('organization', None)
    except Exception as e:
        return None

def load_contexts_from_toml():
    default_toml_path = os.path.expanduser("~/.config/nobl9/config.toml")
    if not os.path.isfile(default_toml_path):
        print("TOML config file not found at expected path:")
        print(f"  {default_toml_path}")
        user_path = input("\nPlease provide the full path to your Nobl9 config.toml file: ").strip()
        if not os.path.isfile(user_path):
            print(f"ERROR: Could not find TOML file at {user_path}")
            return {}
        toml_path = user_path
    else:
        toml_path = default_toml_path
    try:
        toml_data = toml.load(toml_path)
        raw_contexts = toml_data.get("contexts", {})
        parsed_contexts = {}
        
        for ctx_name, creds in raw_contexts.items():
            if "clientId" in creds and "clientSecret" in creds:
                # Check if this is a custom instance (has url field)
                is_custom_instance = "url" in creds
                base_url = creds.get("url")
                okta_org_url = creds.get("oktaOrgURL")
                okta_auth_server = creds.get("oktaAuthServer")
                
                parsed_contexts[ctx_name] = {
                    "clientId": creds["clientId"],
                    "clientSecret": creds["clientSecret"],
                    "accessToken": creds.get("accessToken", ""),
                    "organization": creds.get("organization", None),
                    "is_custom_instance": is_custom_instance,
                    "base_url": base_url,
                    "oktaOrgURL": okta_org_url,
                    "oktaAuthServer": okta_auth_server
                }
        return parsed_contexts
    except Exception as e:
        print(f"Failed to parse TOML config: {e}")
        return {}

def enhanced_choose_context():
    contexts_dict = load_contexts_from_toml()
    if not contexts_dict:
        print("No valid contexts found. Please ensure your config.toml is set up correctly.")
        sys.exit(1)
    context_names = list(contexts_dict.keys())
    if len(context_names) == 1:
        selected = context_names[0]
        return selected, contexts_dict[selected]
    print("\nAvailable contexts:")
    for i, name in enumerate(context_names, 1):
        print(f"  [{i}] {name}")
    choice = input("Select a context: ").strip()
    try:
        index = int(choice) - 1
        selected = context_names[index]
        return selected, contexts_dict[selected]
    except (ValueError, IndexError):
        print("ERROR: Invalid context selection.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

def authenticate(credentials):
    client_id = credentials.get("clientId")
    client_secret = credentials.get("clientSecret")
    if not client_id or not client_secret:
        print("ERROR: Missing credentials in context.")
        sys.exit(1)
    org_id = credentials.get("organization")
    # Try decoding accessToken if organization is not in config
    if not org_id and credentials.get("accessToken"):
        org_id = decode_jwt_payload(credentials["accessToken"])
    # Check for SLOCTL_ORGANIZATION environment variable
    if not org_id:
        org_id = os.getenv("SLOCTL_ORGANIZATION")
    # Fall back to user input if no organization ID is found
    if not org_id:
        org_id = input("Enter Nobl9 Organization ID (find in Nobl9 UI under Settings > Account): ").strip()
    # Validate org_id
    if not org_id:
        print("ERROR: Organization ID is required.")
        sys.exit(1)
    encoded_creds = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded_creds}",
        "Content-Type": "application/json",
        "Organization": org_id
    }
    
    # Check if this is a custom instance with custom base URL
    is_custom_instance = credentials.get("is_custom_instance", False)
    base_url = credentials.get("base_url")
    okta_org_url = credentials.get("oktaOrgURL")
    okta_auth_server = credentials.get("oktaAuthServer")
    
    if is_custom_instance and base_url:
        print(f"API base url: {base_url}")
        #if okta_org_url:
           # print(f"Okta Org URL: {okta_org_url}")
        # Use custom base URL for authentication
        auth_url = f"{base_url}/accessToken"
    else:
        auth_url = "https://app.nobl9.com/api/accessToken"
    
    response = requests.post(auth_url, headers=headers)
    if response.status_code != 200:
        print("ERROR: Authentication failed")
        try:
            error_data = response.json()
            if "error" in error_data:
                error_info = error_data["error"]
                # Check if error is a string (contains nested JSON) or a dict
                if isinstance(error_info, str):
                    try:
                        # Look for JSON object in the error string
                        import re
                        json_match = re.search(r'\{.*\}', error_info)
                        if json_match:
                            nested_error = json.loads(json_match.group())
                            print(f"  Error Code: {nested_error.get('errorCode', 'Unknown')}")
                            print(f"  Summary: {nested_error.get('errorSummary', 'No summary provided')}")
                            print(f"  Error ID: {nested_error.get('errorId', 'No ID provided')}")
                            if nested_error.get('errorCauses'):
                                print(f"  Causes: {nested_error['errorCauses']}")
                        else:
                            # If no JSON found, show the raw error string
                            print(f"  Error: {error_info}")
                    except json.JSONDecodeError:
                        # If nested parsing fails, show the raw error string
                        print(f"  Error: {error_info}")
                else:
                    # Error is already a dictionary
                    print(f"  Error Code: {error_info.get('errorCode', 'Unknown')}")
                    print(f"  Summary: {error_info.get('errorSummary', 'No summary provided')}")
                    print(f"  Error ID: {error_info.get('errorId', 'No ID provided')}")
                    if error_info.get('errorCauses'):
                        print(f"  Causes: {error_info['errorCauses']}")
            elif "message" in error_data:
                print(f"  Message: {error_data['message']}")
            else:
                print(f"  Response: {response.text}")
        except json.JSONDecodeError:
            print(f"  Raw response: {response.text}")
        sys.exit(1)
    
    try:
        token_data = response.json()
        token = token_data.get("access_token")
        if not token:
            print("ERROR: No access token in response")
            print(f"  Response: {response.text}")
            sys.exit(1)
        return token, org_id
    except json.JSONDecodeError:
        print("ERROR: Invalid JSON response from authentication endpoint")
        print(f"  Response: {response.text}")
        sys.exit(1)

def collect_users(token, org, is_custom_instance=False, custom_base_url=None, okta_org_url=None, okta_auth_server=None):
    print("Fetching users...")
    headers = {"Authorization": f"Bearer {token}", "Organization": org}
    
    # Use custom base URL for custom instances
    if is_custom_instance and custom_base_url:
        api_base_url = f"{custom_base_url}/usrmgmt/v2/users?limit=50"
    else:
        api_base_url = "https://app.nobl9.com/api/usrmgmt/v2/users?limit=50"
    next_token = None
    seen_tokens = set()
    all_users = []
    page_count = 0

    while True:
        url = api_base_url
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
            print(f"API error {res.status_code}")
            try:
                error_data = res.json()
                if "error" in error_data:
                    error_info = error_data["error"]
                    # Check if error is a string (contains nested JSON) or a dict
                    if isinstance(error_info, str):
                        try:
                            # Look for JSON object in the error string
                            import re
                            json_match = re.search(r'\{.*\}', error_info)
                            if json_match:
                                nested_error = json.loads(json_match.group())
                                print(f"  Error Code: {nested_error.get('errorCode', 'Unknown')}")
                                print(f"  Summary: {nested_error.get('errorSummary', 'No summary provided')}")
                            else:
                                # If no JSON found, show the raw error string
                                print(f"  Error: {error_info}")
                        except json.JSONDecodeError:
                            # If nested parsing fails, show the raw error string
                            print(f"  Error: {error_info}")
                    else:
                        # Error is already a dictionary
                        print(f"  Error Code: {error_info.get('errorCode', 'Unknown')}")
                        print(f"  Summary: {error_info.get('errorSummary', 'No summary provided')}")
                elif "message" in error_data:
                    print(f"  Message: {error_data['message']}")
                else:
                    print(f"  Response: {res.text}")
            except json.JSONDecodeError:
                print(f"  Raw response: {res.text}")
            break

        data = res.json()
        users = data.get("users", [])
        all_users.extend(users)

        next_token = data.get("paging", {}).get("next")
        page_count += 1
        print(f"  Page {page_count}: Retrieved {len(users)} users (Total: {len(all_users)})")

        if not next_token:
            break

    print(f"✓ User collection complete! Total: {len(all_users)} users")
    return all_users

def fetch_audit_logs(token, org, start_time, end_time, admin_user_ids, is_custom_instance=False, custom_base_url=None, okta_org_url=None, okta_auth_server=None):
    logs = []
    offset = 0
    limit = 100
    
    # Use custom base URL for custom instances
    if is_custom_instance and custom_base_url:
        api_base_url = f"{custom_base_url}/audit/v1/logs"
    else:
        api_base_url = "https://app.nobl9.com/api/audit/v1/logs"
    
    # Add time range validation
    try:
        start_dt = datetime.fromisoformat(start_time.replace('Z', ''))
        end_dt = datetime.fromisoformat(end_time.replace('Z', ''))
        if start_dt > end_dt:
            print("ERROR: Start time is after end time")
            sys.exit(1)
    except ValueError as e:
        print(f"ERROR: Invalid timestamp format: {e}")
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {token}",
        "Organization": org,
        "Accept": "application/json"
    }
    
    print(f"\nFetching audit logs for {len(admin_user_ids)} admin user(s)...")
    print(f"Time range: {start_time} to {end_time}")
    print("Progress:")
    
    # Track pagination state
    total_retrieved = 0
    has_more = True
    
    total_processed = 0
    total_admin_logs = 0
    
    while has_more:
        print(f"  Processing page {offset//limit + 1}...", end="", flush=True)
        params = {
            "limit": limit,
            "offset": offset,
            "sortBy": "timestamp",
            "sortOrder": "desc",
            "from": start_time,
            "to": end_time
        }
        
        # Add actor filter if single admin
        if len(admin_user_ids) == 1:
            params["actor"] = next(iter(admin_user_ids))
        
        try:
            response = requests.get(
                api_base_url,
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code != 200:
                print(f"ERROR: API request failed (Status: {response.status_code})")
                try:
                    error_data = response.json()
                    if "error" in error_data:
                        error_info = error_data["error"]
                        # Check if error is a string (contains nested JSON) or a dict
                        if isinstance(error_info, str):
                            try:
                                # Look for JSON object in the error string
                                import re
                                json_match = re.search(r'\{.*\}', error_info)
                                if json_match:
                                    nested_error = json.loads(json_match.group())
                                    print(f"  Error Code: {nested_error.get('errorCode', 'Unknown')}")
                                    print(f"  Summary: {nested_error.get('errorSummary', 'No summary provided')}")
                                    print(f"  Error ID: {nested_error.get('errorId', 'No ID provided')}")
                                else:
                                    # If no JSON found, show the raw error string
                                    print(f"  Error: {error_info}")
                            except json.JSONDecodeError:
                                # If nested parsing fails, show the raw error string
                                print(f"  Error: {error_info}")
                        else:
                            # Error is already a dictionary
                            print(f"  Error Code: {error_info.get('errorCode', 'Unknown')}")
                            print(f"  Summary: {error_info.get('errorSummary', 'No summary provided')}")
                            print(f"  Error ID: {error_info.get('errorId', 'No ID provided')}")
                    elif "message" in error_data:
                        print(f"  Message: {error_data['message']}")
                    else:
                        print(f"  Response: {response.text}")
                except json.JSONDecodeError:
                    print(f"  Raw response: {response.text}")
                sys.exit(1)
            
            data = response.json()
            page_logs = data.get("data", [])
            
            if not page_logs:
                print("No more logs found")
                break
            
            total_processed += len(page_logs)
            
            # Filter logs for admin actions
            admin_logs = []
            for log in page_logs:
                # Extract user ID from actor object - check both user.id and clientId
                actor = log.get("actor", {})
                actor_id = None
                
                # Check user object first
                user = actor.get("user", {})
                if user:
                    actor_id = user.get("id")
                
                # If no user ID found, try clientId
                if not actor_id:
                    actor_id = actor.get("clientId")
                
                if actor_id in admin_user_ids:
                    admin_logs.append(log)
            
            logs.extend(admin_logs)
            total_admin_logs += len(admin_logs)
            print(f" Found {len(admin_logs)} admin actions")
            
            # Continue if we got a full page
            if len(page_logs) < limit:
                has_more = False
            else:
                offset += len(page_logs)
                
        except Exception as e:
            print(f"\n✗ ERROR: Failed to fetch logs: {e}")
            break
    
    print(f"\n✓ Audit log collection complete!")
    print(f"\nFinal Summary:")
    print(f"Total logs processed: {total_processed}")
    print(f"Total admin logs found: {total_admin_logs}")
    
    # Sort logs by timestamp
    logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    # Count event types
    event_counts = {}
    seen_actions = set()
    for log in logs:
        event = log.get("event", "")
        if not event:
            event = log.get("action", "")  # fallback to action field
        if not event:
            event = "Unknown"  # default for empty events
        seen_actions.add(event)
        event_counts[event] = event_counts.get(event, 0) + 1
    
    print("\nAudit Log Event Types:")
    for event, count in sorted(event_counts.items()):
        print(f"  - {event}: {count} events")
            
    return logs

def select_time_period():
    while True:
        print("\nSelect time period:")
        print("  [1] Past 24 hours")
        print("  [2] Past 7 days")
        print("  [3] Past 14 days")
        print("  [4] Past 30 days")
        print("  [5] Specific day")
        print("  [6] Custom range")
        
        try:
            choice = int(input("Enter choice: "))
            now = datetime.utcnow()
            
            if choice == 1:
                start_time = (now - timedelta(hours=24)).isoformat() + "Z"
                end_time = now.isoformat() + "Z"
                return start_time, end_time
            elif choice == 2:
                start_time = (now - timedelta(days=7)).isoformat() + "Z"
                end_time = now.isoformat() + "Z"
                return start_time, end_time
            elif choice == 3:
                start_time = (now - timedelta(days=14)).isoformat() + "Z"
                end_time = now.isoformat() + "Z"
                return start_time, end_time
            elif choice == 4:
                start_time = (now - timedelta(days=30)).isoformat() + "Z"
                end_time = now.isoformat() + "Z"
                return start_time, end_time
            elif choice == 5:
                day = input("Enter date (YYYY-MM-DD): ")
                start_time = f"{day}T00:00:00Z"
                end_time = f"{day}T23:59:59Z"
                return start_time, end_time
            elif choice == 6:
                start_time = input("Enter start time (YYYY-MM-DDThh:mm:ssZ): ")
                end_time = input("Enter end time (YYYY-MM-DDThh:mm:ssZ): ")
                return start_time, end_time
            else:
                print("ERROR: Invalid choice. Please enter a number between 1 and 6.")
                continue
        except ValueError:
            print("ERROR: Invalid input. Please enter a number.")
            continue

def select_admin_users(users):
    """Allow selection of specific admin users or all admins."""
    print("Identifying admin users...")
    admin_users = [(u["userId"], f"{u.get('firstName', '')} {u.get('lastName', '')}".strip()) 
                  for u in users 
                  if any(role.get("name") == "organization-admin" for role in u.get("roles", []))]
    
    if not admin_users:
        print("✗ No admin users found.")
        sys.exit(1)
    
    print(f"✓ Found {len(admin_users)} admin user(s)")
    
    while True:
        print("\nSelect admin users to audit:")
        print("  [0] All admin users")
        for i, (_, name) in enumerate(admin_users, 1):
            print(f"  [{i}] {name}")
        
        try:
            choice = int(input("Enter choice: "))
            if choice == 0:
                return {uid for uid, _ in admin_users}
            elif 1 <= choice <= len(admin_users):
                return {admin_users[choice-1][0]}
            else:
                print(f"ERROR: Invalid choice. Please enter a number between 0 and {len(admin_users)}.")
                continue
        except ValueError:
            print("ERROR: Invalid input. Please enter a number.")
            continue

def display_and_export_logs(logs, users, context):
    """Format logs into a table and offer export options."""
    import pandas as pd
    from tabulate import tabulate

    # Create user lookup dictionary
    user_lookup = {u.get("userId"): f"{u.get('firstName', '')} {u.get('lastName', '')}".strip() 
                  for u in users}

    # Format logs for display
    rows = []
    for log in logs:
        actor = log.get("actor", {})
        actor_id = actor.get("user", {}).get("id") or actor.get("clientId")
        
        rows.append({
            "Time": log.get("timestamp", "").replace("T", " ").replace("Z", ""),
            "Admin": user_lookup.get(actor_id, actor_id),
            "Action": log.get("event", "")
        })

    print("\nAudit Log Table:")
    print(tabulate(rows, headers="keys", tablefmt="simple"))

    # Export options
    print("\nExport options:")
    print("  [1] CSV")
    print("  [2] JSON (full details)")
    print("  [3] Excel")
    choice = input("\nSelect export format [Enter to skip]: ")


    if not choice:
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    base = f"export_audit_logs/audit_logs_{context}_{timestamp}"
    os.makedirs("export_audit_logs", exist_ok=True)
    df = pd.DataFrame(rows)

    if choice == "1":
        df.to_csv(f"{base}.csv", index=False)
        print(f"Exported to {base}.csv")
    elif choice == "2":
        with open(f"{base}.json", "w") as f:
            json.dump(logs, f, indent=2)  # Export raw logs for full details
        print(f"Exported to {base}.json")
    elif choice == "3":
        df.to_excel(f"{base}.xlsx", index=False)
        print(f"Exported to {base}.xlsx")
    else:
        print("Invalid choice, skipping export")

def main():
    print("Nobl9 Admin Audit Log Tool")
    print("=" * 40)
    
    check_dependencies()
    context_name, credentials = enhanced_choose_context()
    
    # Note: sloctl context switching is not needed for direct API calls
    # but kept for compatibility with other scripts

    token, org = authenticate(credentials)
    if not token or not org:
        print("ERROR: Authentication failed")
        sys.exit(1)
    
    # Get custom instance information from credentials
    is_custom_instance = credentials.get("is_custom_instance", False)
    custom_base_url = credentials.get("base_url")
    okta_org_url = credentials.get("oktaOrgURL")
    okta_auth_server = credentials.get("oktaAuthServer")
    
    users = collect_users(token, org, is_custom_instance, custom_base_url, okta_org_url, okta_auth_server)
    admin_user_ids = select_admin_users(users)  # Replace existing admin_user_ids logic
    
    print(f"\nMonitoring actions for {len(admin_user_ids)} admin user(s)")
    
    start_time, end_time = select_time_period()
    
    audit_logs = fetch_audit_logs(token, org, start_time, end_time, admin_user_ids, is_custom_instance, custom_base_url, okta_org_url, okta_auth_server)
    
    # Replace raw print with formatted display and export
    display_and_export_logs(audit_logs, users, context_name)

if __name__ == "__main__":
    main()