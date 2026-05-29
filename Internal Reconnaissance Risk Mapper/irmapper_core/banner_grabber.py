import socket
import ssl


HTTP_SERVICES = {"HTTP", "HTTP-Alt"}
HTTPS_SERVICES = {"HTTPS", "HTTPS-Alt"}
SSH_SERVICES = {"SSH"}


def grab_ssh_banner(host: str, port: int, timeout: float = 1.5) -> str | None:
    """
    Attempts to read an SSH banner.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(256)
            return banner.decode(errors="ignore").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def grab_http_headers(host: str, port: int, timeout: float = 1.5) -> str | None:
    """
    Sends a minimal HTTP HEAD request and returns response headers.

    This does not authenticate or submit data.
    """
    request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: IRMapper/0.1\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            response = sock.recv(1024)
            return response.decode(errors="ignore").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def grab_https_headers(host: str, port: int, timeout: float = 1.5) -> str | None:
    """
    Sends a minimal HTTPS HEAD request and returns response headers.

    Certificate checks are turned off because this is for internal scanning, and many internal services use self-signed certificates
    """
    request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: IRMapper/0.1\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            raw_sock.settimeout(timeout)

            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                tls_sock.settimeout(timeout)
                tls_sock.sendall(request)
                response = tls_sock.recv(1024)
                return response.decode(errors="ignore").strip()

    except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError):
        return None


def grab_banner_for_service(
    host: str,
    port: int,
    service_name: str,
    timeout: float = 1.5
) -> str | None:
    """
    Selects the correct banner grabbing method based on service name.
    """
    if service_name in SSH_SERVICES:
        return grab_ssh_banner(host, port, timeout)

    if service_name in HTTP_SERVICES:
        return grab_http_headers(host, port, timeout)

    if service_name in HTTPS_SERVICES:
        return grab_https_headers(host, port, timeout)

    return None


def add_banners_to_host_result(
    host_result: dict,
    timeout: float = 1.5
) -> dict:
    """
    Adds banner information to open services for one host.
    """
    enriched_result = host_result.copy()
    enriched_ports = []

    host = host_result["host"]

    for service in host_result.get("open_ports", []):
        enriched_service = service.copy()

        banner = grab_banner_for_service(
            host=host,
            port=enriched_service["port"],
            service_name=enriched_service["service"],
            timeout=timeout
        )

        enriched_service["banner"] = banner
        enriched_ports.append(enriched_service)

    enriched_result["open_ports"] = enriched_ports
    return enriched_result


def add_banners_to_scan_results(
    scan_results: list[dict],
    timeout: float = 1.5
) -> list[dict]:
    """
    Adds banner information to all scan results.
    """
    return [
        add_banners_to_host_result(result, timeout)
        for result in scan_results
    ]