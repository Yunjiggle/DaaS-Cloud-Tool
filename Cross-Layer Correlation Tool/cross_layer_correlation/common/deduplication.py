"""
Deduplication Module for Cross-Layer Correlation
Removes duplicate entries and normalizes data
"""

import pandas as pd
from typing import List


class Deduplicator:
    """
    Handles deduplication and data normalization
    """

    @staticmethod
    def remove_duplicates(
        df: pd.DataFrame,
        subset: List[str] = None,
        keep: str = 'first'
    ) -> pd.DataFrame:
        """
        Remove duplicate rows from DataFrame

        Args:
            df: Input DataFrame
            subset: Column names to consider for identifying duplicates
            keep: Which duplicates to keep ('first', 'last', False)

        Returns:
            DataFrame with duplicates removed
        """
        df = df.copy()
        original_count = len(df)

        if subset:
            df = df.drop_duplicates(subset=subset, keep=keep)
        else:
            df = df.drop_duplicates(keep=keep)

        removed_count = original_count - len(df)

        if removed_count > 0:
            print(f"Removed {removed_count} duplicate entries")

        return df

    @staticmethod
    def normalize_user_identifiers(df: pd.DataFrame, user_col: str) -> pd.DataFrame:
        """
        Normalize user identifiers (trim whitespace, lowercase)

        Args:
            df: Input DataFrame
            user_col: Name of user column

        Returns:
            DataFrame with normalized user identifiers
        """
        df = df.copy()
        df[user_col] = df[user_col].str.strip().str.lower()
        return df

    @staticmethod
    def merge_and_deduplicate(
        dfs: List[pd.DataFrame],
        merge_on: List[str] = None,
        how: str = 'outer'
    ) -> pd.DataFrame:
        """
        Merge multiple DataFrames and remove duplicates

        Args:
            dfs: List of DataFrames to merge
            merge_on: Column names to merge on
            how: Type of merge ('inner', 'outer', 'left', 'right')

        Returns:
            Merged and deduplicated DataFrame
        """
        if not dfs:
            return pd.DataFrame()

        if len(dfs) == 1:
            return dfs[0]

        result = dfs[0]
        for df in dfs[1:]:
            if merge_on:
                result = pd.merge(result, df, on=merge_on, how=how)
            else:
                result = pd.concat([result, df], ignore_index=True)

        return Deduplicator.remove_duplicates(result)
