"""
Timestamp Validator for Cross-Layer Correlation
Validates and normalizes timestamps across different log sources
"""

import pandas as pd
from datetime import datetime, timezone
from typing import List, Dict, Any


class TimestampValidator:
    """
    Validates timestamps and detects inconsistencies across different log sources
    """

    @staticmethod
    def parse_timestamp(timestamp_str: str, format_hint: str = None) -> pd.Timestamp:
        """
        Parse timestamp string to pandas Timestamp

        Args:
            timestamp_str: Timestamp string
            format_hint: Optional format hint ('iso', 'unix_ms', 'unix_s')

        Returns:
            Normalized pandas Timestamp in UTC
        """
        try:
            if format_hint == 'unix_ms':
                # Unix timestamp in milliseconds
                return pd.to_datetime(int(timestamp_str), unit='ms', utc=True)
            elif format_hint == 'unix_s':
                # Unix timestamp in seconds
                return pd.to_datetime(int(timestamp_str), unit='s', utc=True)
            else:
                # Try ISO format or let pandas infer
                return pd.to_datetime(timestamp_str, utc=True)
        except Exception as e:
            raise ValueError(f"Failed to parse timestamp '{timestamp_str}': {e}")

    @staticmethod
    def normalize_timestamps(df: pd.DataFrame, timestamp_col: str, format_hint: str = None) -> pd.DataFrame:
        """
        Normalize timestamps in a DataFrame column

        Args:
            df: Input DataFrame
            timestamp_col: Name of timestamp column
            format_hint: Optional format hint

        Returns:
            DataFrame with normalized timestamps
        """
        df = df.copy()
        df[timestamp_col] = df[timestamp_col].apply(
            lambda x: TimestampValidator.parse_timestamp(str(x), format_hint)
        )
        return df

    @staticmethod
    def detect_inconsistencies(
        timestamps1: List[pd.Timestamp],
        timestamps2: List[pd.Timestamp],
        tolerance_seconds: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Detect timestamp inconsistencies between two log sources

        Args:
            timestamps1: First list of timestamps
            timestamps2: Second list of timestamps
            tolerance_seconds: Tolerance for timestamp matching

        Returns:
            List of detected inconsistencies
        """
        inconsistencies = []

        for i, ts1 in enumerate(timestamps1):
            matched = False
            for j, ts2 in enumerate(timestamps2):
                diff = abs((ts1 - ts2).total_seconds())
                if diff <= tolerance_seconds:
                    matched = True
                    break

            if not matched:
                inconsistencies.append({
                    'index': i,
                    'timestamp': ts1,
                    'status': 'No matching timestamp found within tolerance'
                })

        return inconsistencies

    @staticmethod
    def validate_temporal_boundaries(
        df: pd.DataFrame,
        timestamp_col: str,
        start_time: pd.Timestamp = None,
        end_time: pd.Timestamp = None
    ) -> pd.DataFrame:
        """
        Filter DataFrame by temporal boundaries

        Args:
            df: Input DataFrame
            timestamp_col: Name of timestamp column
            start_time: Optional start time filter
            end_time: Optional end time filter

        Returns:
            Filtered DataFrame
        """
        df = df.copy()

        if start_time is not None:
            df = df[df[timestamp_col] >= start_time]

        if end_time is not None:
            df = df[df[timestamp_col] <= end_time]

        return df
