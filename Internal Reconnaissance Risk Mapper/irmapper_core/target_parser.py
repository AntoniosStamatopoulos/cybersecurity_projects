import ipaddress


def parse_targets(target: str) -> list[str]:
    """
    Converts a single IP or CIDR subnet into a list of IP addresses.
    Raises:
        ValueError: If the target is not a valid IP address or CIDR subnet.
    """
    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]

        ip = ipaddress.ip_address(target)
        return [str(ip)]

    except ValueError as exc:
        raise ValueError(
            f"Invalid target '{target}'. Use a valid IP address or CIDR subnet."
        ) from exc