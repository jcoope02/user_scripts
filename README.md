# Nobl9 User Management Scripts

A collection of Python scripts for managing and auditing users in Nobl9 SLO platform.

## Overview

These scripts provide comprehensive user management capabilities for Nobl9, including user auditing, creation, and detailed user information retrieval. All scripts are designed to work with the Nobl9 API and require proper authentication setup.

## Scripts

### 1. `audit_logs_for_admins_v1.0.py`
**Purpose**: Fetches and analyzes audit logs for admin users in Nobl9.

**Features**:
- Retrieves detailed audit trail information including timestamps and admin actions
- Supports filtering by time periods (24h, 7d, 14d, 30d, specific day, custom range)
- Filters by specific admin users or all admins
- Export options: CSV, JSON (full details), Excel
- Progress indicators and error handling
- User-friendly retry mechanisms for invalid inputs

**Usage**:
```bash
python3 audit_logs_for_admins_v1.0.py
```

**Dependencies**: `requests`, `pandas`, `openpyxl`, `toml`, `tabulate`, `sloctl` CLI

### 2. `users_basic_v1.2.py`
**Purpose**: Retrieves basic user information from Nobl9.

**Features**:
- Lists all users with basic details (name, email, roles)
- Displays user count and role distribution
- Simple table format output
- Error handling and progress indicators

**Usage**:
```bash
python3 users_basic_v1.2.py
```

**Dependencies**: `requests`, `toml`, `tabulate`, `sloctl` CLI

### 3. `creators_v1.0.py`
**Purpose**: Identifies and displays users who have created SLOs in Nobl9.

**Features**:
- Finds users who have created SLOs
- Shows creation counts per user
- Displays SLO details including names and creation dates
- Export capabilities for SLO creator data

**Usage**:
```bash
python3 creators_v1.0.py
```

**Dependencies**: `requests`, `pandas`, `openpyxl`, `toml`, `tabulate`, `sloctl` CLI

### 4. `usersdetailed_v2.0.py`
**Purpose**: Retrieves comprehensive user information including detailed profiles and permissions.

**Features**:
- Detailed user profiles with all available information
- Role and permission analysis
- User activity and status information
- Comprehensive data export options

**Usage**:
```bash
python3 usersdetailed_v2.0.py
```

**Dependencies**: `requests`, `pandas`, `openpyxl`, `toml`, `tabulate`, `sloctl` CLI

## Prerequisites

### Required Software
- Python 3.6 or higher
- `sloctl` CLI tool (install from https://docs.nobl9.com/sloctl/)

### Python Dependencies
Install required packages:
```bash
pip3 install requests pandas openpyxl toml tabulate
```

### Authentication Setup
1. **Configure sloctl**: Set up your Nobl9 credentials using `sloctl config`
2. **Organization ID**: Ensure you have your Nobl9 Organization ID
3. **API Access**: Verify your account has appropriate API permissions

## Configuration

### TOML Configuration
Scripts read configuration from `~/.config/nobl9/config.toml`:
```toml
[contexts.your-context]
clientId = "your-client-id"
clientSecret = "your-client-secret"
accessToken = "your-access-token"
organization = "your-org-id"
```

### Environment Variables
- `SLOCTL_ORGANIZATION`: Set your Nobl9 Organization ID

## Common Features

### Error Handling
All scripts include:
- Comprehensive error messages
- API error parsing and display
- Graceful handling of authentication failures
- Retry mechanisms for user input errors

### Progress Indicators
- Real-time progress updates during data collection
- Clear status messages
- Pagination handling for large datasets

### Export Options
Most scripts support multiple export formats:
- **CSV**: Simple tabular data
- **JSON**: Full API response data
- **Excel**: Formatted spreadsheets with multiple sheets

### User Input Validation
- Input validation with retry mechanisms
- Clear error messages for invalid choices
- Graceful handling of keyboard interrupts

## Usage Examples

### Basic User Audit
```bash
cd /path/to/user_scripts
python3 users_basic_v1.2.py
```

### Admin Activity Audit
```bash
python3 audit_logs_for_admins_v1.0.py
# Follow prompts to select time period and admin users
```

### SLO Creator Analysis
```bash
python3 creators_v1.0.py
# View users who have created SLOs and export data
```

## Output Files

Scripts create output in the following locations:
- **CSV/Excel**: `export_audit_logs/` directory
- **JSON**: Full API responses for detailed analysis
- **Console**: Formatted tables and progress information

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify `sloctl config` is properly set up
   - Check Organization ID in config or environment
   - Ensure API credentials are valid

2. **Missing Dependencies**
   - Run `pip3 install -r requirements.txt` (if available)
   - Install individual packages as needed

3. **Permission Errors**
   - Verify your account has appropriate Nobl9 permissions
   - Check Organization ID matches your access level

4. **API Rate Limits**
   - Scripts include built-in pagination and delays
   - Large datasets may take time to process

### Debug Mode
For troubleshooting, scripts provide detailed error messages and API response information.

## Contributing

When modifying scripts:
1. Update version numbers in script headers
2. Test with different Nobl9 configurations
3. Maintain consistent error handling patterns
4. Update this README for new features

## License

See `LICENSE` file for full license information.

## Support

For issues or questions:
1. Check error messages for specific guidance
2. Verify Nobl9 API documentation
3. Review authentication setup
4. Test with minimal data sets first

---

**Note**: These scripts are designed for Nobl9 SLO platform administration and require appropriate API access permissions. 
