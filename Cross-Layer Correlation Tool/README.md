# DaaS Forensic Investigation - Cross-Layer Correlation Tool

A forensic analysis tool for Desktop-as-a-Service (DaaS) environments supporting Amazon WorkSpaces and Microsoft Azure Virtual Desktop.

## Features

### Cross-Layer Correlation
- **Access Layer**: User authentication logs
- **Control Layer**: VM allocation and network activity logs
- **Resource Layer**: VM disk images and cloud storage (future integration)

### AWS WorkSpaces Support (Dedicated Environment)
- AWS Event Bridge WorkSpaces Access log analysis
- Route 53 DNS Query Log analysis (per user)
- VPC Flow Log analysis (per user)
- Periodic Domain Query detection
- Domain Access Timeline (cloud storage access patterns)
- Port Access Pattern detection (RDP connection analysis)
- User-Workspace-Time mapping generation
- Security threat timeline reconstruction

### Azure Virtual Desktop Support
- Interactive and Non-Interactive Sign-in Log analysis
- User-VM-Time mapping generation
- VM allocation pattern analysis (breadth-first/depth-first)
- Evidence fragmentation detection
- Concurrent access detection

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup

1. Clone or download this repository

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Running the Application

```bash
streamlit run app.py
```

The application will open in your default web browser at `http://localhost:8501`

### AWS WorkSpaces Analysis (Dedicated Environment)

1. Select "AWS WorkSpaces" from the platform dropdown
2. Upload the following files:
   - **Event Bridge Logs**: Multiple CSV files containing WorkSpaces Access events (AWS_EVENT_BRIDGE_*.csv)
   - **Route 53 Query Logs**: Multiple CSV files per user (USER_A_QUERY_LOGS.csv, USER_B_QUERY_LOGS.csv, etc.)
   - **VPC Flow Logs** (Optional): Multiple CSV files per user (USER_A_VPC_LOGS.csv, USER_B_VPC_LOGS.csv, etc.)
3. View analysis results:
   - Summary statistics
   - User-Workspace-Time mapping
   - Security activity detection (Periodic Domain Query, Domain Access Timeline, Port Access Pattern)
   - Results organized by USER for clear attribution
   - Integrated activity timeline

### Azure Virtual Desktop Analysis

1. Select "Azure Virtual Desktop" from the platform dropdown
2. Upload the following files:
   - **Interactive Sign-in Logs**: CSV file (optional)
   - **Non-Interactive Sign-in Logs**: CSV or JSON file (required)
3. View analysis results:
   - Summary statistics
   - VM allocation pattern analysis
   - Evidence fragmentation analysis
   - User-VM session timeline
   - Integrated activity timeline

## Input Data Format

### AWS WorkSpaces (Dedicated Environment)

#### Event Bridge Logs (CSV)
Required columns:
- `timestamp`: Unix timestamp in milliseconds
- `message`: JSON string containing:
  - `time`: Event timestamp (ISO 8601)
  - `detail.workspaceId`: Workspace identifier
  - `detail.clientIpAddress`: Client IP address
  - `detail.actionType`: Action type (e.g., successfulLogin)
  - `detail.clientPlatform`: Client platform

#### Route 53 Query Logs (CSV)
Files should be named with user identifiers (e.g., USER_A_QUERY_LOGS.csv)
Required columns:
- `timestamp`: Unix timestamp in milliseconds
- `message`: JSON string containing:
  - `query_timestamp`: Query timestamp (ISO 8601)
  - `query_name`: Queried domain name
  - `srcaddr`: Source IP address
  - `srcids.instance`: EC2 instance ID

#### VPC Flow Logs (CSV) - Optional
Files should be named with user identifiers (e.g., USER_A_VPC_LOGS.csv)
Required columns:
- `Source IP`: Source IP address
- `Destination IP`: Destination IP address
- `Source Port`: Source port
- `Destination Port`: Destination port
- `Protocol`: Protocol number
- `Bytes`: Number of bytes transferred
- `Start Time`: Start timestamp (Unix)

#### Workspace User Mapping (JSON) - Optional
AWS Event Bridge logs do not include username or email information. To display actual user identities (similar to Azure logs), you can provide an optional mapping file named `workspace_user_mapping.json`:

```json
{
  "workspace_mappings": [
    {
      "workspace_id": "ws-9hbpjtbt0",
      "username": "user-a@example.com",
      "display_name": "User A",
      "user_label": "USER_A"
    },
    {
      "workspace_id": "ws-bdq5d2k76",
      "username": "user-b@example.com",
      "display_name": "User B",
      "user_label": "USER_B"
    }
  ]
}
```

This file should be placed in the same directory as your AWS log files. When provided, the tool will enrich the output with actual usernames and display names.

### Azure Virtual Desktop

#### Non-Interactive Sign-in Logs (CSV/JSON)
Required columns/fields:
- `Date (UTC)` or `Date` or `createdDateTime`: Timestamp
- `Username` or `User` or `userPrincipalName`: User identifier
- `Device ID` or `deviceId`: VM identifier
- `IP address` or `ipAddress`: Source IP address
- `Application`: Application name
- `Request ID`: Unique request identifier

## Output

### User-VM-Time Mapping
- User authentication timeline
- VM allocation periods
- Session start and end times
- IP address assignments

### Security Activity Detection (AWS)
- **Periodic Domain Query**: Repeated DNS queries at regular intervals
- **Domain Access Timeline**: Cloud storage and external domain access patterns
- **Port Access Pattern**: RDP and other port connection analysis
- Activity type, affected user, target domain/port
- Query count, connection attempts, and average intervals
- Temporal boundaries and data volume metrics
- Results organized by USER for clear forensic attribution

### Evidence Fragmentation (Azure)
- Number of VMs used per user
- Session distribution across VMs
- Total session duration
- Concurrent access detection

### Integrated Timeline
- Chronologically sorted events
- User activities
- Security threats (AWS)
- Cross-layer correlation results

## Architecture

```
[7] Final/
├── cross_layer_correlation/
│   ├── __init__.py
│   ├── aws_correlator.py         # AWS WorkSpaces analysis
│   ├── azure_correlator.py       # Azure Virtual Desktop analysis
│   └── common/
│       ├── __init__.py
│       ├── timestamp_validator.py # Timestamp normalization
│       └── deduplication.py       # Data deduplication
├── static/
│   └── css/                       # Custom styles
├── app.py                         # Streamlit UI
├── requirements.txt
└── README.md
```

## Key Modules

### AWS Correlator (`aws_correlator.py`)
- `load_cloudtrail_logs()`: Load and normalize CloudTrail logs
- `load_query_logs()`: Load and parse Route 53 Query Logs
- `generate_user_vm_mapping()`: Create user-VM-time mappings
- `detect_c2_beaconing()`: Detect Periodic Domain Query patterns
- `generate_timeline()`: Generate integrated timeline

### Azure Correlator (`azure_correlator.py`)
- `load_interactive_signin_logs()`: Load Interactive Sign-in Logs
- `load_noninteractive_signin_logs()`: Load Non-Interactive Sign-in Logs
- `generate_user_vm_mapping()`: Create user-VM-time mappings
- `analyze_vm_allocation_pattern()`: Analyze allocation strategy
- `detect_evidence_fragmentation()`: Detect fragmentation across VMs
- `generate_timeline()`: Generate integrated timeline

### Common Utilities
- **TimestampValidator**: Timestamp parsing, normalization, and validation
- **Deduplicator**: Duplicate removal and data normalization

## UI Features

- **Pretendard Font**: Modern, readable typography
- **Wide Layout**: Horizontal display optimized for PC screens
- **Minimal Vertical Scrolling**: Content organized horizontally
- **Interactive Visualizations**: Plotly-based timeline charts
- **Responsive Design**: Adapts to different screen sizes

## Case Study Examples

### AWS WorkSpaces - Security Activity Analysis
- **Scenario**: Periodic Domain Query pattern detection
- **Input**: Event Bridge logs + Route 53 Query Logs + VPC Flow Logs
- **Output**: Detected repeated DNS queries at regular intervals, cloud storage access patterns, and port connection patterns
- **Attribution**: Activities mapped to specific users with clear temporal boundaries
- **Presentation**: Results organized by USER in horizontal layout for forensic review

### Azure Virtual Desktop - Pooled Environment
- **Scenario**: Multi-user pooled VM investigation
- **Input**: Non-Interactive Sign-in Logs
- **Output**: User activities fragmented across 2 VMs with breadth-first allocation
- **Evidence Correlation**: Successfully reconstructed individual user timelines from intermixed logs

## Limitations

- AWS: VM disk images not available in WorkSpaces Pooled environments
- Azure: Requires Non-Interactive Sign-in Logs for VM session tracking
- Timestamp accuracy depends on log source synchronization
- Periodic Domain Query detection uses heuristic thresholds (configurable)

## Future Enhancements

- VDI Artifact Integrator for Resource Layer analysis
- CloudWatch Metrics integration for resource monitoring
- Additional activity detection patterns (lateral movement, privilege escalation)
- Export functionality for investigation reports (PDF, JSON, CSV)
- Advanced visualization options for forensic timeline reconstruction

## References

This tool implements the forensic investigation framework described in:
- "A Forensic Investigation Framework for Desktop-as-a-Service in Cloud Environments" (DFRWS USA 2026)

## License

This tool is developed for academic research and forensic investigation purposes.

## Support

For issues or questions, please refer to the project documentation or contact the development team.
