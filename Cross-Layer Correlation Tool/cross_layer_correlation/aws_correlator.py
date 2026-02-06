"""
AWS Cross-Layer Correlator for WorkSpaces Dedicated Environments
Analyzes Event Bridge, VPC Flow Logs, and Route 53 Query Logs
"""

import pandas as pd
import json
from typing import Dict, List, Tuple, Any
from datetime import datetime, timedelta
from .common.timestamp_validator import TimestampValidator
from .common.deduplication import Deduplicator


class AWSCorrelator:
    """
    AWS WorkSpaces Cross-Layer Correlation Tool (Dedicated Environment)
    """

    def __init__(self):
        self.eventbridge_df = None
        self.query_logs_df = None
        self.vpc_logs_df = None
        self.user_vm_mapping = None
        self.activity_timeline = None
        self.workspace_user_mapping = {}  # Maps workspace_id to user info

    def load_workspace_user_mapping(self, mapping_file: str = None) -> Dict[str, Dict]:
        """
        Load workspace-to-user mapping from JSON file

        Args:
            mapping_file: Path to workspace_user_mapping.json file

        Returns:
            Dictionary mapping workspace_id to user info
        """
        if not mapping_file:
            return {}

        try:
            with open(mapping_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Create mapping dictionary
            mapping = {}
            for entry in data.get('workspace_mappings', []):
                workspace_id = entry.get('workspace_id')
                if workspace_id:
                    mapping[workspace_id] = {
                        'username': entry.get('username', ''),
                        'display_name': entry.get('display_name', ''),
                        'user_label': entry.get('user_label', '')
                    }

            self.workspace_user_mapping = mapping
            return mapping

        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load workspace mapping file: {e}")
            return {}

    def load_eventbridge_logs(self, file_paths: List[str]) -> pd.DataFrame:
        """
        Load AWS Event Bridge WorkSpaces Access logs

        Args:
            file_paths: List of paths to Event Bridge CSV files

        Returns:
            Processed Event Bridge DataFrame
        """
        all_dfs = []

        for file_path in file_paths:
            df = pd.read_csv(file_path)

            # Parse JSON messages
            messages = []
            for _, row in df.iterrows():
                try:
                    msg = json.loads(row['message'])
                    msg['timestamp_ms'] = row['timestamp']
                    messages.append(msg)
                except (json.JSONDecodeError, KeyError):
                    continue

            if messages:
                event_df = pd.DataFrame(messages)
                all_dfs.append(event_df)

        if not all_dfs:
            raise ValueError("No valid Event Bridge data found")

        # Merge all dataframes
        combined_df = pd.concat(all_dfs, ignore_index=True)

        # Normalize timestamps
        combined_df = TimestampValidator.normalize_timestamps(combined_df, 'time')

        # Extract detail fields
        if 'detail' in combined_df.columns:
            detail_df = pd.json_normalize(combined_df['detail'])
            combined_df = pd.concat([combined_df, detail_df], axis=1)

        # Remove duplicates
        combined_df = Deduplicator.remove_duplicates(combined_df, subset=['time', 'workspaceId'])

        # Sort by time
        combined_df = combined_df.sort_values('time').reset_index(drop=True)

        self.eventbridge_df = combined_df
        return combined_df

    def load_query_logs(self, file_paths: List[str], user_labels: List[str] = None) -> pd.DataFrame:
        """
        Load Route 53 Query Logs for multiple users

        Args:
            file_paths: List of paths to Query Logs CSV files
            user_labels: Optional list of user labels (e.g., ['USER_A', 'USER_B'])

        Returns:
            Processed Query Logs DataFrame
        """
        all_dfs = []

        for i, file_path in enumerate(file_paths):
            df = pd.read_csv(file_path)
            user_label = user_labels[i] if user_labels and i < len(user_labels) else f'USER_{i+1}'

            # Parse JSON messages
            messages = []
            for _, row in df.iterrows():
                try:
                    msg = json.loads(row['message'])
                    msg['timestamp_ms'] = row['timestamp']
                    msg['user_label'] = user_label
                    messages.append(msg)
                except json.JSONDecodeError:
                    continue

            if messages:
                query_df = pd.DataFrame(messages)
                all_dfs.append(query_df)

        if not all_dfs:
            raise ValueError("No valid Query Logs data found")

        # Merge all dataframes
        combined_df = pd.concat(all_dfs, ignore_index=True)

        # Normalize timestamps
        combined_df = TimestampValidator.normalize_timestamps(combined_df, 'query_timestamp')

        # Add timestamp from milliseconds
        combined_df['timestamp'] = pd.to_datetime(combined_df['timestamp_ms'], unit='ms', utc=True)

        # Extract instance ID from srcids field
        if 'srcids' in combined_df.columns:
            combined_df['instance_id'] = combined_df['srcids'].apply(
                lambda x: x.get('instance', None) if isinstance(x, dict) else None
            )

        # Sort by time
        combined_df = combined_df.sort_values('query_timestamp').reset_index(drop=True)

        self.query_logs_df = combined_df
        return combined_df

    def load_vpc_logs(self, file_paths: List[str], user_labels: List[str] = None) -> pd.DataFrame:
        """
        Load VPC Flow Logs for multiple users

        Args:
            file_paths: List of paths to VPC Flow Logs CSV files
            user_labels: Optional list of user labels

        Returns:
            Processed VPC Flow Logs DataFrame
        """
        all_dfs = []

        for i, file_path in enumerate(file_paths):
            df = pd.read_csv(file_path)
            user_label = user_labels[i] if user_labels and i < len(user_labels) else f'USER_{i+1}'
            df['user_label'] = user_label

            # Rename columns for consistency
            column_mapping = {
                'Source IP': 'srcaddr',
                'Destination IP': 'dstaddr',
                'Source Port': 'srcport',
                'Destination Port': 'dstport',
                'Protocol': 'protocol',
                'Bytes': 'bytes',
                'Action': 'action'
            }
            df = df.rename(columns=column_mapping)

            # Convert timestamp (check if it's in milliseconds or seconds)
            if 'timestamp' in df.columns:
                # Check if timestamp is in milliseconds (typical value > 1e12)
                if df['timestamp'].iloc[0] > 1e12:
                    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='ms', utc=True)
                else:
                    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s', utc=True)
            elif 'Start Time' in df.columns:
                # Check if timestamp is in milliseconds (typical value > 1e12)
                if df['Start Time'].iloc[0] > 1e12:
                    df['timestamp'] = pd.to_datetime(df['Start Time'], unit='ms', utc=True)
                else:
                    df['timestamp'] = pd.to_datetime(df['Start Time'], unit='s', utc=True)

            all_dfs.append(df)

        if not all_dfs:
            raise ValueError("No valid VPC Flow Logs data found")

        # Merge all dataframes
        combined_df = pd.concat(all_dfs, ignore_index=True)

        # Sort by time
        if 'timestamp' in combined_df.columns:
            combined_df = combined_df.sort_values('timestamp').reset_index(drop=True)

        self.vpc_logs_df = combined_df
        return combined_df

    def generate_user_vm_mapping(self) -> pd.DataFrame:
        """
        Generate user-VM-time mapping table from Event Bridge logs

        Returns:
            User-VM mapping DataFrame
        """
        if self.eventbridge_df is None:
            raise ValueError("Event Bridge logs not loaded")

        sessions = []

        # Build workspace to user mapping
        workspace_user_map = {}

        if self.query_logs_df is not None:
            # Get unique user labels and workspace IDs
            user_labels = sorted(self.query_logs_df['user_label'].unique())
            workspace_ids = sorted(self.eventbridge_df['workspaceId'].unique())

            # Method 1: Try to match by instance_id
            if 'instance_id' in self.query_logs_df.columns:
                for user_label in user_labels:
                    user_queries = self.query_logs_df[self.query_logs_df['user_label'] == user_label]
                    instance_ids = user_queries['instance_id'].dropna().unique()

                    for instance_id in instance_ids:
                        # Find workspace that contains this instance ID
                        for ws_id in workspace_ids:
                            if instance_id in ws_id or ws_id in instance_id:
                                workspace_user_map[ws_id] = user_label
                                break

            # Method 2: If instance_id matching failed, map by order (1st user → 1st workspace)
            if not workspace_user_map:
                for i, ws_id in enumerate(workspace_ids):
                    if i < len(user_labels):
                        workspace_user_map[ws_id] = user_labels[i]

        # Group by workspace ID
        for workspace_id, group in self.eventbridge_df.groupby('workspaceId'):
            group = group.sort_values('time')

            # Get user label for this workspace
            user_label = workspace_user_map.get(workspace_id, 'Unknown')

            # Enrich with username from workspace mapping if available
            username = user_label
            display_name = user_label
            if workspace_id in self.workspace_user_mapping:
                mapping_info = self.workspace_user_mapping[workspace_id]
                if mapping_info.get('username'):
                    username = mapping_info['username']
                if mapping_info.get('display_name'):
                    display_name = mapping_info['display_name']

            for _, event in group.iterrows():
                session = {
                    'User': user_label,
                    'Username': username,
                    'Display Name': display_name,
                    'Workspace ID': workspace_id,
                    'Client IP': event.get('clientIpAddress', 'N/A'),
                    'Action': event.get('actionType', 'N/A'),
                    'Login Time': event.get('loginTime', event['time']),
                    'Platform': event.get('clientPlatform', 'N/A'),
                    'Product': event.get('workspacesClientProductName', 'N/A'),
                    'Session Start': event['time'],
                    'Session End': event['time'] + pd.Timedelta(hours=1)  # Estimate
                }

                sessions.append(session)

        mapping_df = pd.DataFrame(sessions)
        self.user_vm_mapping = mapping_df
        return mapping_df

    def _find_user_label(self, client_ip: str) -> str:
        """Find user label from IP address correlation"""
        if self.query_logs_df is None or not client_ip:
            return None

        # Match by source IP in query logs
        matching = self.query_logs_df[self.query_logs_df['srcaddr'].str.contains(client_ip.split('.')[2], na=False)]
        if len(matching) > 0:
            return matching.iloc[0]['user_label']

        return None

    def detect_data_exfiltration(self) -> pd.DataFrame:
        """
        Detect data exfiltration patterns using Query Logs and VPC Logs

        Returns:
            DataFrame with detected data exfiltration patterns
        """
        activities = []

        if self.query_logs_df is None:
            return pd.DataFrame(activities)

        # Detect cloud storage access patterns
        cloud_storage_domains = ['drive.google.com', 'dropbox.com', 'onedrive.live.com',
                                 'box.com', 'drive.com']

        for user_label, group in self.query_logs_df.groupby('user_label'):
            for domain in cloud_storage_domains:
                domain_queries = group[group['query_name'].str.contains(domain, case=False, na=False)]

                if len(domain_queries) > 0:
                    # Add each query as individual entry
                    for _, query in domain_queries.iterrows():
                        # Check for outbound traffic in VPC logs
                        if self.vpc_logs_df is not None:
                            user_vpc = self.vpc_logs_df[self.vpc_logs_df['user_label'] == user_label]

                            # Port 443 outbound traffic
                            https_traffic = user_vpc[
                                (user_vpc['dstport'] == 443) | (user_vpc['dstport'] == '443')
                            ]

                            if len(https_traffic) > 0:
                                total_bytes = pd.to_numeric(https_traffic['bytes'], errors='coerce').sum()

                                if total_bytes > 100000:  # > 100KB
                                    activities.append({
                                        'Activity Type': 'Domain Access Timeline',
                                        'User': user_label,
                                        'Domain': query['query_name'],
                                        'Query Count': 1,
                                        'Start Time': query['query_timestamp'],
                                        'End Time': query['query_timestamp'],
                                        'Total Bytes': int(total_bytes),
                                        'Port': 443,
                                        'Details': f'{total_bytes/1024/1024:.2f} MB transferred to {query["query_name"]}'
                                    })

        activity_df = pd.DataFrame(activities)
        return activity_df

    def detect_rdp_bruteforce(self) -> pd.DataFrame:
        """
        Detect Port Access Patterns in VPC Flow Logs

        Returns:
            DataFrame with detected port access patterns
        """
        activities = []

        if self.vpc_logs_df is None:
            return pd.DataFrame(activities)

        # Group by user and destination port 3389
        rdp_logs = self.vpc_logs_df[
            (self.vpc_logs_df['dstport'] == 3389) | (self.vpc_logs_df['dstport'] == '3389')
        ]

        for user_label, group in rdp_logs.groupby('user_label'):
            # Count connection attempts
            connection_attempts = len(group)

            if connection_attempts >= 1:  # Detect any RDP port access
                activities.append({
                    'Activity Type': 'Port Access Pattern',
                    'User': user_label,
                    'Attempts': connection_attempts,
                    'Start Time': group['timestamp'].min() if 'timestamp' in group.columns else None,
                    'End Time': group['timestamp'].max() if 'timestamp' in group.columns else None,
                    'Source IPs': ', '.join(group['srcaddr'].unique()[:5]),
                    'Details': f'{connection_attempts} RDP port (3389) connection attempts'
                })

        activity_df = pd.DataFrame(activities)
        return activity_df

    def detect_c2_beaconing(self, interval_threshold: int = 100, min_occurrences: int = 1) -> pd.DataFrame:
        """
        Detect Periodic Domain Query patterns in Query Logs

        Returns:
            DataFrame with detected periodic domain query patterns
        """
        if self.query_logs_df is None:
            return pd.DataFrame()

        activities = []

        # Exclude common legitimate domains
        exclude_domains = ['microsoft.com', 'windows.com', 'amazon.com', 'amazonaws.com']

        for user_label, user_group in self.query_logs_df.groupby('user_label'):
            for query_name, query_group in user_group.groupby('query_name'):
                # Skip excluded domains
                if any(exc in query_name for exc in exclude_domains):
                    continue

                # Check if this is a suspicious pattern (c2-server-*.example.com)
                is_suspicious_pattern = 'c2-server' in query_name.lower() or 'c2server' in query_name.lower()

                # For suspicious patterns, detect immediately (no min occurrence needed)
                if is_suspicious_pattern:
                    timestamps = query_group['query_timestamp'].sort_values()
                    activities.append({
                        'Activity Type': 'Periodic Domain Query',
                        'User': user_label,
                        'Domain': query_name,
                        'Query Count': len(query_group),
                        'Start Time': timestamps.iloc[0],
                        'End Time': timestamps.iloc[-1] if len(timestamps) > 1 else timestamps.iloc[0],
                        'Avg Interval (s)': 'N/A',
                        'Std Interval (s)': 'N/A'
                    })
                    continue

                # For other domains, check minimum occurrences
                if len(query_group) < min_occurrences:
                    continue

                # Calculate time intervals
                timestamps = query_group['query_timestamp'].sort_values()
                intervals = timestamps.diff().dt.total_seconds().dropna()

                if len(intervals) > 0:
                    avg_interval = intervals.mean()
                    std_interval = intervals.std()

                    if avg_interval <= interval_threshold and std_interval < 10:
                        activities.append({
                            'Activity Type': 'Periodic Domain Query',
                            'User': user_label,
                            'Domain': query_name,
                            'Query Count': len(query_group),
                            'Start Time': timestamps.iloc[0],
                            'End Time': timestamps.iloc[-1],
                            'Avg Interval (s)': round(avg_interval, 2),
                            'Std Interval (s)': round(std_interval, 2)
                        })

        activity_df = pd.DataFrame(activities)
        return activity_df

    def detect_all_activities(self) -> pd.DataFrame:
        """
        Run all threat detection methods and combine results

        Returns:
            Combined threat DataFrame
        """
        all_activities = []

        # Periodic Domain Query
        c2_activities = self.detect_c2_beaconing()
        if len(c2_activities) > 0:
            all_activities.append(c2_activities)

        # Domain Access Timeline
        exfil_activities = self.detect_data_exfiltration()
        if len(exfil_activities) > 0:
            all_activities.append(exfil_activities)

        # Port Access Pattern
        rdp_activities = self.detect_rdp_bruteforce()
        if len(rdp_activities) > 0:
            all_activities.append(rdp_activities)

        if all_activities:
            combined = pd.concat(all_activities, ignore_index=True)
            self.activity_timeline = combined
            return combined
        else:
            self.activity_timeline = pd.DataFrame()
            return pd.DataFrame()

    def generate_timeline(self) -> pd.DataFrame:
        """
        Generate integrated timeline with user activities and threats

        Returns:
            Integrated timeline DataFrame
        """
        timeline = []

        # Build workspace to user mapping (same as in generate_user_vm_mapping)
        workspace_user_map = {}
        if self.query_logs_df is not None and self.eventbridge_df is not None:
            user_labels = sorted(self.query_logs_df['user_label'].unique())
            workspace_ids = sorted(self.eventbridge_df['workspaceId'].unique())

            # Try instance_id matching
            if 'instance_id' in self.query_logs_df.columns:
                for user_label in user_labels:
                    user_queries = self.query_logs_df[self.query_logs_df['user_label'] == user_label]
                    instance_ids = user_queries['instance_id'].dropna().unique()
                    for instance_id in instance_ids:
                        for ws_id in workspace_ids:
                            if instance_id in ws_id or ws_id in instance_id:
                                workspace_user_map[ws_id] = user_label
                                break

            # Fallback to order-based mapping
            if not workspace_user_map:
                for i, ws_id in enumerate(workspace_ids):
                    if i < len(user_labels):
                        workspace_user_map[ws_id] = user_labels[i]

        # Add login events
        if self.eventbridge_df is not None:
            for _, event in self.eventbridge_df.iterrows():
                workspace_id = event.get('workspaceId', 'N/A')
                user = workspace_user_map.get(workspace_id, 'Unknown')
                timeline.append({
                    'Timestamp': event['time'],
                    'User': user,
                    'Event Type': 'Login',
                    'Event Name': event.get('actionType', 'N/A'),
                    'Details': f"Workspace: {workspace_id}, "
                              f"IP: {event.get('clientIpAddress', 'N/A')}",
                    'Source': 'Event Bridge'
                })

        # Add threat events
        if self.activity_timeline is not None and len(self.activity_timeline) > 0:
            for _, threat in self.activity_timeline.iterrows():
                timeline.append({
                    'Timestamp': threat.get('Start Time', pd.Timestamp.now(tz='UTC')),
                    'User': threat['User'],
                    'Event Type': 'Threat Detected',
                    'Event Name': threat['Activity Type'],
                    'Details': threat.get('Details', ''),
                    'Source': 'Threat Detection'
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

        if self.eventbridge_df is not None:
            stats['total_login_events'] = len(self.eventbridge_df)
            stats['unique_workspaces'] = self.eventbridge_df['workspaceId'].nunique()

        if self.query_logs_df is not None:
            stats['total_dns_queries'] = len(self.query_logs_df)
            stats['unique_domains'] = self.query_logs_df['query_name'].nunique()
            stats['unique_users'] = self.query_logs_df['user_label'].nunique()

        if self.vpc_logs_df is not None:
            stats['total_network_flows'] = len(self.vpc_logs_df)

        if self.activity_timeline is not None and len(self.activity_timeline) > 0:
            stats['activities_detected'] = len(self.activity_timeline)
            stats['activity_types'] = self.activity_timeline['Activity Type'].unique().tolist()
        else:
            stats['activities_detected'] = 0
            stats['activity_types'] = []

        if self.user_vm_mapping is not None:
            stats['total_sessions'] = len(self.user_vm_mapping)

        return stats
