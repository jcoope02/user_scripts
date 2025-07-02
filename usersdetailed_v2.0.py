#!/usr/bin/env python3


import os
import base64
import requests
import json
from datetime import datetime


def check_dependencies():
    for pkg in ["toml", "pandas", "openpyxl", "tabulate", "requests"]:
        try:
            pass
        except ImportError:
            print(f"Missing required package: {pkg}")
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
    try:
        choice = input("Select a context: ").strip()
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
    return res.json().get("access_token")


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


def fetch_user_detail(user_id, token, org):
    headers = {"Authorization": f"Bearer {token}", "Organization": org}
    res = requests.get(f"https://app.nobl9.com/api/usrmgmt/v2/users/{user_id}", headers=headers)
    if res.ok:
        return res.json()
    return None


def parse_roles_and_projects(detail):
    roles = set()
    projects = set()
    project_roles = []

    rb = detail.get("roleBindings", {})
    direct = rb.get("direct", {})
    groups = rb.get("groups", [])

    for r in direct.get("organizationRoles", []):
        roles.add(r.get("displayName", r.get("name", "N/A")))

    for p in direct.get("projects", []):
        project_name = p.get("displayName", p.get("name", ""))
        projects.add(project_name)
        for r in p.get("roles", []):
            role_name = r.get("displayName", r.get("name", "N/A"))
            project_roles.append(f"{project_name}: {role_name}")

    for g in groups:
        for r in g.get("organizationRoles", []):
            roles.add(r.get("displayName", r.get("name", "N/A")))
        for p in g.get("projects", []):
            project_name = p.get("displayName", p.get("name", ""))
            projects.add(project_name)
            for r in p.get("roles", []):
                role_name = r.get("displayName", r.get("name", "N/A"))
                project_roles.append(f"{project_name}: {role_name}")

    return (
        "; ".join(sorted(roles)),
        "; ".join(sorted(project_roles)),
        "; ".join(sorted(projects))
    )


def export_and_display(users, context, org, flag, args):
    import pandas as pd
    from tabulate import tabulate

    rows = []
    for u in users:
        name = f"{u.get('firstName', '')} {u.get('lastName', '')}".strip()
        email = u.get("email", "")
        status = u.get("status", "")
        user_id = u.get("userId", "")

        org_roles, project_roles, projects = parse_roles_and_projects(u)

        rows.append({
            "Name": name,
            "Email": email,
            "OrgRoles": org_roles,
            "ProjectRoles": project_roles,
            "Status": status,
            "Projects": projects,
            "UserID": user_id,
        })

    print("\nDetailed Nobl9 User Table:")
    print(tabulate(rows, headers="keys", tablefmt="github"))

    if not flag:
        choice = input("\nExport? [1] CSV  [2] JSON  [3] XLSX  [Enter to skip]: ").strip()
    else:
        choice = {"c": "1", "j": "2", "x": "3"}.get(flag.lower(), "")

    if not choice:
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    base = f"export_users_detailed/users-{context}_{timestamp}"
    os.makedirs("export_users_detailed", exist_ok=True)
    df = pd.DataFrame(rows)

    if choice == "1":
        df.to_csv(f"{base}.csv", index=False)
        print(f"Exported to {base}.csv")
    elif choice == "2":
        with open(f"{base}.json", "w") as f:
            json.dump(users, f, indent=2)
        print(f"Exported to {base}.json")
    elif choice == "3":
        df.to_excel(f"{base}.xlsx", index=False)
        print(f"Exported to {base}.xlsx")


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


def main():
    import argparse
    check_dependencies()
    parser = argparse.ArgumentParser(description="Fetch detailed Nobl9 user info.")
    parser.add_argument("-c", action="store_true", help="Export as CSV")
    parser.add_argument("-j", action="store_true", help="Export as JSON")
    parser.add_argument("-x", action="store_true", help="Export as XLSX")
    parser.add_argument("--context", help="Context name from config.toml")
    parser.add_argument("--org", help="Organization name")
    args = parser.parse_args()

    contexts = load_contexts_from_toml()
    context = choose_context(contexts, args.context)
    creds = contexts[context]
    
    # Extract org from existing token in TOML
    org = None
    if stored_token := creds.get("accessToken"):
        org = decode_jwt_payload(stored_token)
        if org:
            print(f"Found organization from stored token: {org}")
    
    # Allow override from command line
    org = args.org or org or input("Enter Nobl9 Organization name: ").strip()
    
    # Always get a fresh token
    client_id = creds["clientId"]
    client_secret = creds["clientSecret"]
    token = get_token(client_id, client_secret, org)
    print(f"\nUsing organization: {org}")

    user_summaries = fetch_users(token, org)

    print(f"\nFetching details for {len(user_summaries)} users...")
    users = []
    for i, u in enumerate(user_summaries, 1):
        uid = u.get("userId")
        name = f"{u.get('firstName', '')} {u.get('lastName', '')}".strip()
        print(f"  [{i}/{len(user_summaries)}] {name}")
        detail = fetch_user_detail(uid, token, org)
        if detail:
            users.append(detail)

    flag = "c" if args.c else "j" if args.j else "x" if args.x else None
    export_and_display(users, context, org, flag, args)


if __name__ == "__main__":
    main()