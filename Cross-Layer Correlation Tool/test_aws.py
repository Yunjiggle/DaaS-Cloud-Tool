"""
AWS Correlator Test Script - Automatic File Loading
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from cross_layer_correlation.aws_correlator import AWSCorrelator

def main():
    print("=" * 80)
    print("AWS WorkSpaces Forensic Analysis - Automatic Test")
    print("=" * 80)
    print()

    # File paths (relative to project root)
    project_root = Path(__file__).parent.parent
    aws_log_dir = project_root / "[1] AWS Log" / "(1) Dedicated"

    # Event Bridge logs
    eventbridge_files = [
        aws_log_dir / "AWS_EVENT_BRIDGE_1.csv",
        aws_log_dir / "AWS_EVENT_BRIDGE_2.csv",
        aws_log_dir / "AWS_EVENT_BRIDGE_3.csv",
        aws_log_dir / "AWS_EVENT_BRIDGE_4.csv",
        aws_log_dir / "AWS_EVENT_BRIDGE_5.csv",
        aws_log_dir / "AWS_EVENT_BRIDGE_6.csv",
    ]

    # Query logs
    query_files = [
        aws_log_dir / "USER_A_QUERY_LOGS.csv",
        aws_log_dir / "USER_B_QUERY_LOGS.csv",
    ]
    query_labels = ["USER_A", "USER_B"]

    # VPC logs
    vpc_files = [
        aws_log_dir / "USER_A_VPC_LOGS.csv",
        aws_log_dir / "USER_B_VPC_LOGS.csv",
    ]
    vpc_labels = ["USER_A", "USER_B"]

    # Check if files exist
    print("Checking files...")
    all_files = eventbridge_files + query_files + vpc_files
    for f in all_files:
        if f.exists():
            print(f"  ✓ {f.name}")
        else:
            print(f"  ✗ {f.name} (NOT FOUND)")
            return

    print()
    print("=" * 80)
    print("Loading and analyzing logs...")
    print("=" * 80)
    print()

    # Initialize correlator
    correlator = AWSCorrelator()

    # Load workspace user mapping
    mapping_file = aws_log_dir / "workspace_user_mapping.json"
    if mapping_file.exists():
        print("0. Loading workspace-user mapping...")
        correlator.load_workspace_user_mapping(str(mapping_file))
        print(f"   ✓ Loaded mapping for {len(correlator.workspace_user_mapping)} workspaces")
        print()

    try:
        # Load Event Bridge logs
        print("1. Loading Event Bridge logs...")
        eventbridge_df = correlator.load_eventbridge_logs([str(f) for f in eventbridge_files if f.exists()])
        print(f"   ✓ Loaded {len(eventbridge_df)} login events")
        print()

        # Load Query logs
        print("2. Loading Route 53 Query logs...")
        query_logs_df = correlator.load_query_logs([str(f) for f in query_files if f.exists()], query_labels)
        print(f"   ✓ Loaded {len(query_logs_df)} DNS queries")
        print()

        # Load VPC logs
        print("3. Loading VPC Flow logs...")
        vpc_logs_df = correlator.load_vpc_logs([str(f) for f in vpc_files if f.exists()], vpc_labels)
        print(f"   ✓ Loaded {len(vpc_logs_df)} network flows")
        print()

        # Generate user-VM mapping
        print("4. Generating user-workspace-time mapping...")
        user_vm_mapping = correlator.generate_user_vm_mapping()
        print(f"   ✓ Generated {len(user_vm_mapping)} session mappings")
        print()

        # Detect activities
        print("5. Detecting security activities...")
        activity_timeline = correlator.detect_all_activities()
        print(f"   ✓ Detected {len(activity_timeline)} activities")
        print()

        # Get summary statistics
        stats = correlator.get_summary_statistics()

        print("=" * 80)
        print("ANALYSIS RESULTS")
        print("=" * 80)
        print()

        # Summary Statistics
        print("📊 Summary Statistics:")
        print(f"  • Login Events: {stats.get('total_login_events', 0)}")
        print(f"  • Unique Users: {stats.get('unique_users', 0)}")
        print(f"  • DNS Queries: {stats.get('total_dns_queries', 0)}")
        print(f"  • Network Flows: {stats.get('total_network_flows', 0)}")
        print(f"  • Activities Detected: {stats.get('activities_detected', 0)}")
        print(f"  • Total Sessions: {stats.get('total_sessions', 0)}")
        print()

        # User-Workspace Mapping
        print("🔗 User-Workspace-Time Mapping:")
        if len(user_vm_mapping) > 0:
            for _, session in user_vm_mapping.iterrows():
                user_display = session['User']
                if 'Username' in session and session['Username'] != session['User']:
                    user_display = f"{session['User']} ({session['Username']})"
                if 'Display Name' in session and session['Display Name'] != session['User']:
                    user_display += f" - {session['Display Name']}"

                print(f"  • {user_display} → Workspace: {session['Workspace ID']}")
                print(f"    - Session: {session['Session Start']} ~ {session['Session End']}")
                print(f"    - Client IP: {session['Client IP']}")
                print(f"    - Platform: {session['Platform']}")
                print()
        else:
            print("  No mapping data found")
            print()

        # Activity Detection
        if len(activity_timeline) > 0:
            print("🚨 Security Activities Detected:")
            for _, activity in activity_timeline.iterrows():
                print(f"\n  ⚠️  {activity['Activity Type']} - User: {activity['User']}")

                if 'Domain' in activity and str(activity['Domain']) != 'nan':
                    print(f"      Domain: {activity['Domain']}")
                if 'Query Count' in activity and str(activity['Query Count']) != 'nan':
                    print(f"      Queries: {activity['Query Count']}")
                if 'Avg Interval (s)' in activity and str(activity['Avg Interval (s)']) != 'nan':
                    print(f"      Avg Interval: {activity['Avg Interval (s)']}s")
                if 'Attempts' in activity and str(activity['Attempts']) != 'nan':
                    print(f"      Attempts: {activity['Attempts']}")
                if 'Total Bytes' in activity and str(activity['Total Bytes']) != 'nan':
                    print(f"      Bytes: {activity['Total Bytes']:,}")
                if 'Details' in activity and str(activity['Details']) != 'nan':
                    print(f"      Details: {activity['Details']}")

                if 'Start Time' in activity and str(activity['Start Time']) != 'nan':
                    print(f"      Time: {activity['Start Time']} ~ {activity.get('End Time', 'N/A')}")
            print()
        else:
            print("🚨 Security Activities: None detected")
            print()

        print("=" * 80)
        print("Analysis completed successfully!")
        print("=" * 80)

    except Exception as e:
        print(f"\n❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return

if __name__ == "__main__":
    main()
