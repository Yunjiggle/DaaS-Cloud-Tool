"""
Azure Correlator Test Script - Automatic File Loading
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from cross_layer_correlation.azure_correlator import AzureCorrelator

def main():
    print("=" * 80)
    print("Azure Virtual Desktop Forensic Analysis - Automatic Test")
    print("=" * 80)
    print()

    # File paths (relative to project root)
    project_root = Path(__file__).parent.parent
    azure_log_dir = project_root / "[6] Azure Log"

    # Sign-in logs
    noninteractive_file = azure_log_dir / "NonInteractiveSignIns_2025-12-14_2025-12-20.csv"
    interactive_file = azure_log_dir / "InteractiveSignIns_AuthDetails_2025-12-14_2025-12-20.csv"

    # Check if files exist
    print("Checking files...")
    if noninteractive_file.exists():
        print(f"  ✓ {noninteractive_file.name}")
    else:
        print(f"  ✗ {noninteractive_file.name} (NOT FOUND)")
        return

    if interactive_file.exists():
        print(f"  ✓ {interactive_file.name}")
    else:
        print(f"  ⚠ {interactive_file.name} (NOT FOUND - Optional)")

    print()
    print("=" * 80)
    print("Loading and analyzing logs...")
    print("=" * 80)
    print()

    # Initialize correlator
    correlator = AzureCorrelator()

    try:
        # Load Non-Interactive Sign-in logs
        print("1. Loading Non-Interactive Sign-in logs...")
        noninteractive_df = correlator.load_noninteractive_signin_logs(str(noninteractive_file))
        print(f"   ✓ Loaded {len(noninteractive_df)} sign-in events")
        print()

        # Load Interactive Sign-in logs (optional)
        if interactive_file.exists():
            print("2. Loading Interactive Sign-in logs...")
            interactive_df = correlator.load_interactive_signin_logs(str(interactive_file))
            print(f"   ✓ Loaded {len(interactive_df)} interactive sign-in events")
            print()

        # Generate user-VM mapping
        print("3. Generating user-VM-time mapping...")
        user_vm_mapping = correlator.generate_user_vm_mapping()
        print(f"   ✓ Generated {len(user_vm_mapping)} session mappings")
        print()

        # Analyze VM allocation pattern
        print("4. Analyzing VM allocation pattern...")
        allocation_analysis = correlator.analyze_vm_allocation_pattern()
        print(f"   ✓ Strategy: {allocation_analysis['allocation_strategy']}")
        print(f"   ✓ Concurrent sessions: {allocation_analysis['concurrent_access_count']}")
        print()

        # Detect evidence fragmentation
        print("5. Detecting evidence fragmentation...")
        fragmentation = correlator.detect_evidence_fragmentation()
        print(f"   ✓ Analyzed fragmentation for {len(fragmentation)} users")
        print()

        # Get summary statistics
        stats = correlator.get_summary_statistics()

        print("=" * 80)
        print("ANALYSIS RESULTS")
        print("=" * 80)
        print()

        # Summary Statistics
        print("📊 Summary Statistics:")
        print(f"  • Sign-in Events: {stats.get('total_noninteractive_signins', 0)}")
        print(f"  • Unique Users: {stats.get('unique_users', 0)}")
        print(f"  • Total Sessions: {stats.get('total_sessions', 0)}")
        print(f"  • Unique VMs: {stats.get('unique_vms', 0)}")
        print()

        # VM Allocation Pattern
        print("🖥️  VM Allocation Pattern:")
        print(f"  • Strategy: {allocation_analysis['allocation_strategy']}")
        print(f"  • Concurrent Access: {allocation_analysis['concurrent_access_count']} sessions")
        print()

        # Evidence Fragmentation
        if len(fragmentation) > 0:
            print("📦 Evidence Fragmentation:")
            for _, frag in fragmentation.iterrows():
                print(f"\n  • User: {frag['User']}")
                print(f"    - Total Sessions: {frag['Total Sessions']}")
                print(f"    - Unique VMs: {frag['Unique VMs']}")
                print(f"    - VM List: {frag['VM List']}")
                print(f"    - Duration: {frag['Total Duration']}")
            print()
        else:
            print("📦 Evidence Fragmentation: No data")
            print()

        # User-VM Mapping
        print("🔗 User-VM Session Timeline:")
        if len(user_vm_mapping) > 0:
            for _, session in user_vm_mapping.head(10).iterrows():
                print(f"  • {session['User']} → VM: {session['VM Identifier']}")
                print(f"    - Session: {session['Session Start']} ~ {session['Session End']}")
                print(f"    - IP: {session['IP Address']}")
                print(f"    - Events: {session.get('Event Count', 'N/A')}")
                print()
        else:
            print("  No mapping data found")
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
