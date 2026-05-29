# this module takes the final results and creates a .json file with them

import json
from datetime import datetime, timezone
from pathlib import Path

from irmapper_core.utils import ensure_directory_exists


def build_summary(results: list[dict]) -> dict:
    """
    Builds a high-level summary from scan results.
    """
    hosts_with_open_ports = [
        result for result in results
        if result.get("open_ports")
    ]

    return {
        "hosts_scanned": len(results),
        "hosts_with_open_ports": len(hosts_with_open_ports),
        "high_risk_hosts": sum(
            1 for result in results
            if result.get("risk_level") == "High"
        ),
        "medium_risk_hosts": sum(
            1 for result in results
            if result.get("risk_level") == "Medium"
        ),
        "low_risk_hosts": sum(
            1 for result in results
            if result.get("risk_level") == "Low"
        ),
        "total_findings": sum(
            len(result.get("findings", []))
            for result in results
        ),
    }


def build_report(
    target: str,
    results: list[dict],
    ports_config_path: str,
    risk_rules_path: str
) -> dict:
    """
    Builds the full structured report.
    """
    return {
        "tool": "Internal Reconnaissance Risk Mapper",
        "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "configuration": {
            "ports_config": ports_config_path,
            "risk_rules": risk_rules_path,
        },
        "summary": build_summary(results),
        "results": results,
    }


def save_json_report(report: dict, output_path: str | Path) -> None:
    """
    Saves the report as JSON.
    """
    path = Path(output_path)
    ensure_directory_exists(path.parent)

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)


def print_terminal_summary(report: dict) -> None:
    """
    Prints a short terminal summary from a report dictionary.
    """
    summary = report["summary"]

    print()
    print("=== Report Summary ===")
    print(f"Hosts scanned: {summary['hosts_scanned']}")
    print(f"Hosts with open ports: {summary['hosts_with_open_ports']}")
    print(f"High risk hosts: {summary['high_risk_hosts']}")
    print(f"Medium risk hosts: {summary['medium_risk_hosts']}")
    print(f"Low risk hosts: {summary['low_risk_hosts']}")
    print(f"Total findings: {summary['total_findings']}")
