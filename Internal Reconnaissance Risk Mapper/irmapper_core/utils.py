# It does not perform scanning, calculate risk, or create findings. It contains small general-purpose functions that can be used by many other files.

from datetime import datetime, timezone
from pathlib import Path
import ipaddress

import yaml


def load_yaml_file(path: str | Path) -> dict:
    """
    Loads a YAML file and returns its content as a Python dictionary.
    """
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"Config file not found: {file_path}")

    with file_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise ValueError(f"YAML file must contain a dictionary/object: {file_path}")

    return data


def ensure_directory_exists(path: str | Path) -> None:
    """
    Creates a directory if it does not already exist.
    """
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)


def utc_timestamp() -> str:
    """
    Returns the current UTC timestamp in ISO 8601 format.
    """
    return datetime.now(timezone.utc).isoformat()


def clean_string(value: str | None, max_length: int = 200) -> str | None:
    """
    Cleans a string by removing excessive whitespace and limiting its length.
    """
    if value is None:
        return None

    cleaned = " ".join(str(value).split())
    return cleaned[:max_length]


def sort_ip_addresses(ips: list[str]) -> list[str]:
    """
    Sorts a list of IP addresses numerically.
    """
    return sorted(ips, key=lambda ip: ipaddress.ip_address(ip))