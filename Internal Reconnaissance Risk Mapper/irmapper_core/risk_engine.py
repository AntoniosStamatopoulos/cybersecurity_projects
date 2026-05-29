# this module takes classified scan results and adds them in every host



def get_risk_level(score: int) -> str:
    """
    Converts a numeric risk score into a risk level.

    Score ranges:
        0-30    Low
        31-69   Medium
        70-100  High
    """
    if score >= 70:
        return "High"

    if score >= 31:
        return "Medium"

    return "Low"


def build_finding(service: dict, rule: dict) -> dict:
    """
    Builds a finding dictionary for one discovered service.
    """
    return {
        "title": rule.get("finding", f"{service.get('service')} exposure"),
        "severity": rule.get("severity", "Low"),
        "service": service.get("service"),
        "port": service.get("port"),
        "category": service.get("category"),
        "exposure_type": service.get("exposure_type", "unknown_exposure"),
        "description": (
            f"{service.get('service')} is reachable on "
            f"{service.get('port')}/tcp from the scanned network."
        ),
        "recommendation": rule.get(
            "recommendation",
            "Review whether this service should be reachable from this network."
        ),
    }


def calculate_host_risk(host_result: dict, risk_rules: dict) -> dict:
    """
    Calculates risk score and findings for one host.
    """
    total_score = 0
    findings = []

    for service in host_result.get("open_ports", []):
        service_name = service.get("service")
        rule = risk_rules.get(service_name)

        if not rule:
            continue

        score = int(rule.get("score", 0))
        total_score += score

        findings.append(build_finding(service, rule))

    total_score = min(total_score, 100)
    risk_level = get_risk_level(total_score)

    enriched_result = host_result.copy()
    enriched_result["risk_score"] = total_score
    enriched_result["risk_level"] = risk_level
    enriched_result["findings"] = findings

    return enriched_result


def calculate_risk_for_scan_results(
    scan_results: list[dict],
    risk_rules_config: dict
) -> list[dict]:
    """
    Calculates risk for all scan results.

    """
    risk_rules = risk_rules_config.get("risk_rules", {})

    return [
        calculate_host_risk(result, risk_rules)
        for result in scan_results
    ]