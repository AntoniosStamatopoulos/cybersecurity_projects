# this file takes the open ports from the scanner and make the information more understandable




SENSITIVE_CATEGORIES = {
    "file_sharing",
    "database",
    "identity",
    "management",
    "devops_admin",
}

ADMIN_CATEGORIES = {
    "web_admin",
    "management",
    "monitoring",
    "devops_admin",
}

EXPOSURE_TYPES = {
    "remote_access": "remote_administration_risk",
    "web": "web_service_exposure",
    "web_admin": "possible_admin_interface",
    "file_sharing": "internal_lateral_movement_risk",
    "database": "data_exposure_risk",
    "identity": "identity_infrastructure_exposure",
    "infrastructure": "infrastructure_service_exposure",
    "mail": "mail_service_exposure",
    "management": "management_plane_exposure",
    "monitoring": "monitoring_data_exposure",
    "devops": "development_service_exposure",
    "devops_admin": "critical_control_plane_exposure",
}


def classify_service(service: dict) -> dict:
    """
    Adds classification metadata to a discovered service.
    """
    category = service.get("category", "unknown")

    classified_service = service.copy()

    classified_service["exposure_type"] = EXPOSURE_TYPES.get(
        category,
        "unknown_exposure"
    )

    classified_service["is_sensitive"] = category in SENSITIVE_CATEGORIES
    classified_service["is_admin_interface"] = category in ADMIN_CATEGORIES

    return classified_service


def classify_host_result(host_result: dict) -> dict:
    """
    Adds classification metadata to all open services for one host.
    """
    classified_result = host_result.copy()

    classified_result["open_ports"] = [
        classify_service(service)
        for service in host_result.get("open_ports", [])
    ]

    return classified_result


def classify_scan_results(scan_results: list[dict]) -> list[dict]:
    """
    Adds classification metadata to all scan results.
    """
    return [
        classify_host_result(result)
        for result in scan_results
    ]