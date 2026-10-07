from typing import Dict, Any


def parse_log_row(row) -> Dict[str, Any]:
    """
    Convert one raw CSV row into a normal Python dictionary.

    The normalizer will later convert this dictionary
    into a SecurityEvent.
    """

    return {
        column: row[column]
        for column in row.index
        if row[column] is not None
    }