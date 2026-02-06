"""
Azure Cross-Layer Correlator for Virtual Desktop Environments
Analyzes Sign-in Logs to generate user-VM-time mappings
"""

import pandas as pd
from typing import Dict, List, Any
from datetime import datetime, timedelta
from .common.timestamp_validator import TimestampValidator
from .common.deduplication import Deduplicator


class AzureCorrelator:
    """
    Azure Virtual Desktop Cross-Layer Correlation Tool
    """

    def __init__(self):
        self.interactive_signin_df = None
        self.noninteractive_signin_df = None
        self.user_vm_mapping = None
        self.activity_timeline = None
        self.vm_name_mapping = {}  # Maps device_id to VM name

    def load_interactive_signin_logs(self, file_path: str) -> pd.DataFrame:
        """
        Load Interactive Sign-in Logs

        Args:
            file_path: Path to Interactive Sign-in CSV file

        Returns:
            Processed Interactive Sign-in DataFrame
        """
        df = pd.read_csv(file_path, encoding='utf-8-sig')

        # Normalize timestamps
        if 'Date' in df.columns:
            df = TimestampValidator.normalize_timestamps(df, 'Date')

        # Remove duplicates
        if 'Request ID' in df.columns:
            df = Deduplicator.remove_duplicates(df, subset=['Request ID'])

        # Sort by time
        if 'Date' in df.columns:
            df = df.sort_values('Date').reset_index(drop=True)

        self.interactive_signin_df = df
        return df

    def load_noninteractive_signin_logs(self, file_path: str) -> pd.DataFrame:
        """
        Load Non-Interactive Sign-in Logs

        Args:
            file_path: Path to Non-Interactive Sign-in CSV/JSON file

        Returns:
            Processed Non-Interactive Sign-in DataFrame
        """
        # Try to load as CSV first, then JSON
        try:
            if file_path.endswith('.json'):
                df = pd.read_json(file_path)
            else:
                df = pd.read_csv(file_path, encoding='utf-8-sig')
        except Exception as e:
            raise ValueError(f"Failed to load file: {e}")

        # Normalize timestamps
        timestamp_col = None
        for col in ['Date (UTC)', 'Date', 'createdDateTime']:
            if col in df.columns:
                timestamp_col = col
                break

        if timestamp_col:
            df = TimestampValidator.normalize_timestamps(df, timestamp_col)
            # Only rename if the column name is different from 'Date'
            if timestamp_col != 'Date':
                # Drop existing 'Date' column if it exists to avoid duplicates
                if 'Date' in df.columns:
                    df = df.drop(columns=['Date'])
                df = df.rename(columns={timestamp_col: 'Date'})

        # Normalize user identifiers
        user_col = None
        for col in ['Username', 'User', 'userPrincipalName']:
            if col in df.columns:
                user_col = col
                break

        if user_col:
            df = Deduplicator.normalize_user_identifiers(df, user_col)
            # Only rename if the column name is different from 'User'
            if user_col != 'User':
                # Drop existing 'User' column if it exists to avoid duplicates
                if 'User' in df.columns:
                    df = df.drop(columns=['User'])
                df = df.rename(columns={user_col: 'User'})

        # Remove duplicates
        if 'Request ID' in df.columns:
            df = Deduplicator.remove_duplicates(df, subset=['Request ID'])

        # Sort by time
        if 'Date' in df.columns:
            df = df.sort_values('Date').reset_index(drop=True)

        self.noninteractive_signin_df = df
        return df

    def _generate_vm_name(self, device_id: str) -> str:
        """
        Generate a short VM name from Device ID

        Args:
            device_id: Full Device ID (GUID)

        Returns:
            Short VM name (e.g., "VM-2987fff8c377")
        """
        if not device_id or device_id == 'Unknown':
            return 'Unknown'

        # Check if mapping already exists
        if device_id in self.vm_name_mapping:
            return self.vm_name_mapping[device_id]

        # Extract last segment of GUID (after last dash)
        parts = str(device_id).split('-')
        if len(parts) > 1:
            short_id = parts[-1]  # Last 12 characters
        else:
            short_id = str(device_id)[:12]

        # Create VM name
        vm_name = f"VM-{short_id}"
        self.vm_name_mapping[device_id] = vm_name

        return vm_name

    def generate_user_vm_mapping(self) -> pd.DataFrame:
        """
        Generate user-VM-time mapping table from Sign-in logs

        Returns:
            User-VM mapping DataFrame
        """
        if self.noninteractive_signin_df is None:
            raise ValueError("Non-Interactive Sign-in logs not loaded.")

        # Use Non-Interactive logs for VM session tracking
        df = self.noninteractive_signin_df.copy()

        sessions = []

        # Check if User column exists, if not find it
        user_col = 'User'
        if 'User' not in df.columns:
            for col in ['Username', 'userPrincipalName', 'user']:
                if col in df.columns:
                    user_col = col
                    break

        # Group by user
        unique_users = list(df[user_col].drop_duplicates())
        for user in unique_users:
            user_events = df[df[user_col] == user].copy()

            # Group by Device ID or IP address to identify VM sessions
            device_col = None
            for col in ['Device ID', 'deviceId', 'IP address', 'ipAddress']:
                if col in user_events.columns:
                    device_col = col
                    break

            if not device_col:
                # Fallback: create sessions from consecutive events
                for i, event in user_events.iterrows():
                    device_id = 'Unknown'
                    session = {
                        'User': user,
                        'VM Identifier': device_id,
                        'VM Name': self._generate_vm_name(device_id),
                        'Session Start': event['Date'],
                        'Session End': event['Date'] + pd.Timedelta(minutes=30),
                        'IP Address': event.get('IP address', event.get('ipAddress', 'N/A')),
                        'Application': event.get('Application', 'N/A'),
                        'Request ID': event.get('Request ID', 'N/A')
                    }
                    sessions.append(session)
                continue

            # Group by device/IP to identify VM sessions
            for device_id, device_group in user_events.groupby(device_col):
                device_group = device_group.sort_values('Date')

                # Create session from first to last event on this device
                device_id_str = str(device_id)
                session = {
                    'User': user,
                    'VM Identifier': device_id_str,
                    'VM Name': self._generate_vm_name(device_id_str),
                    'Session Start': device_group['Date'].min(),
                    'Session End': device_group['Date'].max() + pd.Timedelta(minutes=30),
                    'IP Address': device_group.get('IP address', device_group.get('ipAddress', pd.Series(['N/A']))).iloc[0],
                    'Application': device_group.get('Application', pd.Series(['N/A'])).iloc[0],
                    'Event Count': len(device_group),
                    'Request IDs': ', '.join(device_group.get('Request ID', pd.Series(['N/A'])).astype(str).head(3))
                }
                sessions.append(session)

        mapping_df = pd.DataFrame(sessions)
        mapping_df = mapping_df.sort_values('Session Start').reset_index(drop=True)

        self.user_vm_mapping = mapping_df
        return mapping_df

    def analyze_vm_allocation_pattern(self) -> Dict[str, Any]:
        """
        Analyze VM allocation patterns (breadth-first vs depth-first)

        Returns:
            Dictionary with allocation pattern analysis
        """
        if self.user_vm_mapping is None:
            raise ValueError("User-VM mapping not generated.")

        analysis = {}

        # Count unique VMs per user
        vm_per_user = self.user_vm_mapping.groupby('User')['VM Identifier'].nunique()
        analysis['vm_per_user'] = vm_per_user.to_dict()

        # Count users per VM
        users_per_vm = self.user_vm_mapping.groupby('VM Identifier')['User'].nunique()
        analysis['users_per_vm'] = users_per_vm.to_dict()

        # Identify allocation strategy
        avg_vms_per_user = vm_per_user.mean()
        avg_users_per_vm = users_per_vm.mean()

        if avg_vms_per_user > 1.5:
            analysis['allocation_strategy'] = 'Breadth-First (users spread across multiple VMs)'
        else:
            analysis['allocation_strategy'] = 'Depth-First (users concentrated on fewer VMs)'

        # Concurrent access detection
        concurrent_sessions = []
        unique_vms = list(self.user_vm_mapping['VM Identifier'].drop_duplicates())
        for vm_id in unique_vms:
            vm_sessions = self.user_vm_mapping[self.user_vm_mapping['VM Identifier'] == vm_id]

            for i, session1 in vm_sessions.iterrows():
                overlaps = vm_sessions[
                    (vm_sessions['Session Start'] <= session1['Session End']) &
                    (vm_sessions['Session End'] >= session1['Session Start']) &
                    (vm_sessions.index != i) &
                    (vm_sessions['User'] != session1['User'])
                ]

                if len(overlaps) > 0:
                    concurrent_sessions.append({
                        'VM': vm_id,
                        'User1': session1['User'],
                        'User2': overlaps.iloc[0]['User'],
                        'Overlap Start': max(session1['Session Start'], overlaps.iloc[0]['Session Start']),
                        'Overlap End': min(session1['Session End'], overlaps.iloc[0]['Session End'])
                    })

        analysis['concurrent_sessions'] = concurrent_sessions
        analysis['concurrent_access_count'] = len(concurrent_sessions)

        return analysis

    def generate_timeline(self) -> pd.DataFrame:
        """
        Generate integrated timeline with user activities

        Returns:
            Integrated timeline DataFrame
        """
        timeline = []

        # Add sign-in events
        if self.noninteractive_signin_df is not None:
            for _, event in self.noninteractive_signin_df.iterrows():
                timeline.append({
                    'Timestamp': event['Date'],
                    'User': event['User'],
                    'Event Type': 'Sign-in',
                    'Event Name': 'Non-Interactive Sign-in',
                    'Details': f"App: {event.get('Application', 'N/A')}, "
                              f"IP: {event.get('IP address', event.get('ipAddress', 'N/A'))}",
                    'Source': 'Azure Sign-in Logs'
                })

        timeline_df = pd.DataFrame(timeline)
        if len(timeline_df) > 0:
            timeline_df = timeline_df.sort_values('Timestamp').reset_index(drop=True)

        return timeline_df

    def get_summary_statistics(self) -> Dict[str, Any]:
        """
        Get summary statistics of the analysis

        Returns:
            Dictionary with summary statistics
        """
        stats = {}

        if self.interactive_signin_df is not None:
            stats['total_interactive_signins'] = len(self.interactive_signin_df)

        if self.noninteractive_signin_df is not None:
            stats['total_noninteractive_signins'] = len(self.noninteractive_signin_df)
            stats['unique_users'] = self.noninteractive_signin_df['User'].nunique()

        if self.user_vm_mapping is not None:
            stats['total_sessions'] = len(self.user_vm_mapping)
            stats['unique_vms'] = self.user_vm_mapping['VM Identifier'].nunique()

        if self.activity_timeline is not None and len(self.activity_timeline) > 0:
            stats['activities_detected'] = len(self.activity_timeline)
            stats['activity_types'] = self.activity_timeline['Activity Type'].unique().tolist()
        else:
            stats['activities_detected'] = 0
            stats['activity_types'] = []

        return stats

    def detect_failed_logins(self) -> pd.DataFrame:
        """
        Detect failed login attempts patterns

        Returns:
            DataFrame with detected failed login patterns
        """
        activities = []

        if self.interactive_signin_df is None:
            return pd.DataFrame(activities)

        # Look for failed authentication attempts
        if 'Status' not in self.interactive_signin_df.columns:
            return pd.DataFrame(activities)

        failed_logins = self.interactive_signin_df[
            self.interactive_signin_df['Status'].str.contains('Failure|failure|Failed|failed', case=False, na=False)
        ]

        if len(failed_logins) > 0:
            for user, group in failed_logins.groupby('User'):
                if len(group) >= 1:  # Detect any failed login
                    # Get IP address
                    if 'IP address' in group.columns:
                        ips = ', '.join(group['IP address'].unique()[:5])
                    elif 'ipAddress' in group.columns:
                        ips = ', '.join(group['ipAddress'].unique()[:5])
                    else:
                        ips = 'N/A'

                    activities.append({
                        'Activity Type': 'Failed Login Attempt',
                        'User': user,
                        'Attempts': len(group),
                        'Start Time': group['Date'].min(),
                        'End Time': group['Date'].max(),
                        'IPs': ips,
                        'Details': f'{len(group)} failed login attempts detected'
                    })

        return pd.DataFrame(activities)

    def detect_rapid_vm_switching(self) -> pd.DataFrame:
        """
        Detect rapid VM switching patterns

        Returns:
            DataFrame with detected rapid VM switching
        """
        activities = []

        if self.user_vm_mapping is None:
            return pd.DataFrame(activities)

        # Group by user and detect VM switching
        for user in list(self.user_vm_mapping['User'].drop_duplicates()):
            user_sessions = self.user_vm_mapping[self.user_vm_mapping['User'] == user].copy()
            user_sessions = user_sessions.sort_values('Session Start')

            # Check for multiple VMs in short time
            unique_vms = list(user_sessions['VM Identifier'].drop_duplicates())
            if len(unique_vms) > 1:
                # Calculate time differences between VM switches
                vm_switches = []
                for i in range(len(user_sessions) - 1):
                    current_vm = user_sessions.iloc[i]['VM Identifier']
                    next_vm = user_sessions.iloc[i + 1]['VM Identifier']
                    if current_vm != next_vm:
                        time_diff = (user_sessions.iloc[i + 1]['Session Start'] -
                                   user_sessions.iloc[i]['Session End']).total_seconds()
                        vm_switches.append(time_diff)

                if len(vm_switches) > 0 and min(vm_switches) < 3600:  # Within 1 hour
                    activities.append({
                        'Activity Type': 'Rapid VM Switching',
                        'User': user,
                        'VM Count': len(unique_vms),
                        'Switch Count': len(vm_switches),
                        'Start Time': user_sessions['Session Start'].min(),
                        'End Time': user_sessions['Session End'].max(),
                        'VM List': ', '.join(unique_vms[:5]),
                        'Details': f'User switched between {len(unique_vms)} VMs with minimum interval of {int(min(vm_switches))}s'
                    })

        return pd.DataFrame(activities)

    def detect_multiple_ip_access(self) -> pd.DataFrame:
        """
        Detect multiple IP access patterns

        Returns:
            DataFrame with detected multiple IP access patterns
        """
        activities = []

        if self.user_vm_mapping is None:
            return pd.DataFrame(activities)

        # Group by user and detect multiple IPs
        for user in list(self.user_vm_mapping['User'].drop_duplicates()):
            user_sessions = self.user_vm_mapping[self.user_vm_mapping['User'] == user]

            # Get unique IPs
            unique_ips = list(user_sessions['IP Address'].drop_duplicates())

            if len(unique_ips) > 1:
                activities.append({
                    'Activity Type': 'Multiple IP Access',
                    'User': user,
                    'IP Count': len(unique_ips),
                    'Start Time': user_sessions['Session Start'].min(),
                    'End Time': user_sessions['Session End'].max(),
                    'IPs': ', '.join(unique_ips[:5]),
                    'Details': f'User accessed from {len(unique_ips)} different IP addresses'
                })

        return pd.DataFrame(activities)

    def detect_all_activities(self) -> pd.DataFrame:
        """
        Run all activity detection methods and combine results

        Returns:
            Combined activity DataFrame
        """
        all_activities = []

        # Failed Login Attempts
        failed_logins = self.detect_failed_logins()
        if len(failed_logins) > 0:
            all_activities.append(failed_logins)

        # Rapid VM Switching
        vm_switching = self.detect_rapid_vm_switching()
        if len(vm_switching) > 0:
            all_activities.append(vm_switching)

        # Multiple IP Access
        ip_access = self.detect_multiple_ip_access()
        if len(ip_access) > 0:
            all_activities.append(ip_access)

        if all_activities:
            combined = pd.concat(all_activities, ignore_index=True)
            self.activity_timeline = combined
            return combined
        else:
            self.activity_timeline = pd.DataFrame()
            return pd.DataFrame()

    def detect_evidence_fragmentation(self) -> pd.DataFrame:
        """
        Detect evidence fragmentation across VMs

        Returns:
            DataFrame with fragmentation analysis per user
        """
        if self.user_vm_mapping is None:
            raise ValueError("User-VM mapping not generated.")

        fragmentation = []

        unique_users = list(self.user_vm_mapping['User'].drop_duplicates())
        for user in unique_users:
            user_sessions = self.user_vm_mapping[self.user_vm_mapping['User'] == user]

            vm_list = list(user_sessions['VM Identifier'].drop_duplicates())
            fragmentation.append({
                'User': user,
                'Total Sessions': len(user_sessions),
                'Unique VMs': user_sessions['VM Identifier'].nunique(),
                'VM List': ', '.join(map(str, vm_list)),
                'First Session': user_sessions['Session Start'].min(),
                'Last Session': user_sessions['Session End'].max(),
                'Total Duration': str(user_sessions['Session End'].max() - user_sessions['Session Start'].min())
            })

        fragmentation_df = pd.DataFrame(fragmentation)
        return fragmentation_df
