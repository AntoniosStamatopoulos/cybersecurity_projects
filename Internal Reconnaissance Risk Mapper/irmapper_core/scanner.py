import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Checks whether a TCP port is open on a host.

    This performs a simple TCP connection attempt.
    It does not authenticate, exploit, or modify the target system.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_host(host: str, ports: list[dict], timeout: float = 1.0) -> dict:
    """
    Scans one host against a list of port definitions.
    """
    open_ports = []

    for port_info in ports:
        port = int(port_info["port"])

        if is_port_open(host, port, timeout):
            open_ports.append({
                "port": port,
                "service": port_info.get("service", "Unknown"),
                "category": port_info.get("category", "unknown")
            })

    return {
        "host": host,
        "open_ports": open_ports
    }


def scan_targets(
    hosts: list[str],
    ports: list[dict],
    threads: int = 50,
    timeout: float = 1.0
) -> list[dict]:
    """
    Scans multiple hosts concurrently.
    Returns: List of scan results, one dictionary per host.
    """
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_host = {
            executor.submit(scan_host, host, ports, timeout): host
            for host in hosts
        }

        for future in as_completed(future_to_host):
            host = future_to_host[future]

            try:
                result = future.result()
                results.append(result)
            except Exception as error:
                results.append({
                    "host": host,
                    "open_ports": [],
                    "error": str(error)
                })

    return sorted(results, key=lambda item: item["host"])