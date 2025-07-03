# Nobl9 User Scripts Collection

A comprehensive collection of Python scripts for interacting with the Nobl9 API, providing various administrative and data retrieval capabilities.

## Overview

This collection includes scripts for:
- User management and analysis
- Audit log retrieval and analysis
- SLO and project metadata retrieval
- Error Budget Adjustment (EBA) creation

All scripts support both standard Nobl9 instances and custom instances, with consistent authentication and error handling patterns.

## Prerequisites

### Required Software
- Python 3.6 or higher
- `sloctl` CLI tool (install from https://docs.nobl9.com/sloctl/)

### Required Python Packages
```bash
pip3 install requests pandas openpyxl toml tabulate PyYAML
```

### Configuration
All scripts use the Nobl9 TOML configuration file located at:
- **Default**: `~/.config/nobl9/config.toml`
- **Custom**: Can be specified at runtime

## Scripts Overview

### 1. `audit_logs_for_admins_v1.0.py`
**Purpose**: Fetches and analyzes audit logs for admin users in Nobl9
**Features**:
- Retrieves detailed audit trail information including timestamps and admin actions
- Supports filtering by time periods and specific admin users
- Export options: CSV, JSON, and Excel formats
- Progress indicators and detailed error handling
- Supports custom Nobl9 instances

**Usage**: `python3 audit_logs_for_admins_v1.0.py`

### 2. `creators_v1.0.py`
**Purpose**: Retrieves ownership metadata (CreatedBy, CreatedAt, UpdatedAt) for SLOs and Projects
**Features**:
- Displays creator information in human-readable format
- Export options: CSV and Excel formats
- Supports custom Nobl9 instances

**Usage**: `python3 creators_v1.0.py`

### 3. `users_basic_v1.2.py`
**Purpose**: Fetches basic user information from Nobl9 API
**Features**:
- Displays user names and IDs in simple table format
- Export options: CSV, JSON, and Excel formats
- Command-line arguments for automation
- Supports custom Nobl9 instances

**Usage**: 
- Interactive: `python3 users_basic_v1.2.py`
- Auto-export: `python3 users_basic_v1.2.py -c` (CSV), `-j` (JSON), `-x` (Excel)

### 4. `usersdetailed_v2.0.py`
**Purpose**: Fetches detailed user information including roles and projects
**Features**:
- Comprehensive user details with role and project assignments
- Export options: CSV, JSON, and Excel formats
- Command-line arguments for automation
- Supports custom Nobl9 instances

**Usage**:
- Interactive: `python3 usersdetailed_v2.0.py`
- Auto-export: `python3 usersdetailed_v2.0.py -c` (CSV), `-j` (JSON), `-x` (Excel)

### 5. `eba_script_v1.0.py`
**Purpose**: Creates Error Budget Adjustment YAMLs for SLOs
**Features**:
- Interactive SLO data fetching from Nobl9
- Template-based YAML generation
- Project and service-based filtering
- Color-coded terminal output
- Supports custom Nobl9 instances

**Usage**: `python3 eba_script_v1.0.py`

## Common Features

### Authentication
All scripts use the same authentication pattern:
1. Load credentials from TOML configuration
2. Support for custom Nobl9 instances (detected via `url` field in TOML)
3. Automatic organization detection from stored tokens
4. Fallback to user input for organization ID

### Custom Instance Support
Scripts automatically detect and support custom Nobl9 instances:
- Detects `url` field in TOML configuration
- Uses custom base URL for all API calls
- Maintains backward compatibility with standard instances

### Error Handling
Consistent error handling across all scripts:
- Detailed API error parsing and display
- Graceful handling of network timeouts
- User-friendly error messages
- Proper exit codes for automation

### Export Options
Most scripts support multiple export formats:
- **CSV**: Simplified tabular data
- **JSON**: Full API response data
- **Excel**: Formatted spreadsheet with multiple sheets

## Configuration

### TOML Configuration Structure
```toml
[contexts]
[contexts.your-context]
clientId = "your-client-id"
clientSecret = "your-client-secret"
accessToken = "optional-stored-token"
organization = "optional-org-id"

# For custom instances:
url = "https://your-custom-instance.com"
oktaOrgURL = "https://your-org.okta.com"
oktaAuthServer = "your-auth-server"
```

### Environment Variables
- `SLOCTL_ORGANIZATION`: Default organization ID (optional)

## Troubleshooting

### Common Issues

1. **"sloctl is not installed"**
   - Install sloctl from https://docs.nobl9.com/sloctl/

2. **"Missing required Python packages"**
   - Run: `pip3 install requests pandas openpyxl toml tabulate PyYAML`

3. **"TOML config file not found"**
   - Ensure your Nobl9 configuration is set up
   - Provide the correct path to your config.toml file

4. **"Authentication failed"**
   - Verify your client ID and secret in the TOML file
   - Check your organization ID
   - Ensure your credentials have the necessary permissions

5. **"API request failed"**
   - Check your network connection
   - Verify the API endpoint is accessible
   - Check for rate limiting

### Custom Instance Issues
- Ensure the `url` field in your TOML config points to the correct custom instance
- Verify the custom instance is accessible from your network
- Check that your credentials work with the custom instance

## File Structure

```
user_scripts/
├── README.md                           # This file
├── audit_logs_for_admins_v1.0.py      # Admin audit log retrieval
├── creators_v1.0.py                   # SLO/Project creator metadata
├── users_basic_v1.2.py                # Basic user information
├── usersdetailed_v2.0.py              # Detailed user information
├── eba_script_v1.0.py                 # Error Budget Adjustment creation
└── export_*/                           # Export directories (created automatically)
    ├── export_audit_logs/
    ├── export_users_basic/
    └── export_users_detailed/
```

## Contributing

When adding new scripts:
1. Follow the existing authentication pattern
2. Include comprehensive error handling
3. Support custom instances
4. Add proper documentation
5. Update this README

## License

This collection is provided as-is for Nobl9 administrators and users.
