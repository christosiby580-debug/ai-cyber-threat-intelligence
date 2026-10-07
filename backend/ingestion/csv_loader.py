import pandas as pd


def load_csv(file_path: str) -> pd.DataFrame:
    """
    Load a CSV security log file into a pandas DataFrame.
    """

    try:
        df = pd.read_csv(file_path)
        return df

    except FileNotFoundError:
        raise FileNotFoundError(f"CSV file not found: {file_path}")

    except Exception as error:
        raise RuntimeError(f"Failed to load CSV file: {error}")