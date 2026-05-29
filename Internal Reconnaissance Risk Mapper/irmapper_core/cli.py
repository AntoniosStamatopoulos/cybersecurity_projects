import argparse
from pathlib import Path


# this is the handler for all services at other programs


#temporary
from irmapper_core.target_parser import parse_targets
from irmapper_core.scanner import scan_targets
from irmapper_core.utils import load_yaml_file, ensure_directory_exists
from irmapper_core.banner_grabber import add_banners_to_scan_results
from irmapper_core.service_classifier import classify_scan_results
from irmapper_core.risk_engine import calculate_risk_for_scan_results
from irmapper_core.reporter import build_report, save_json_report, print_terminal_summary




DEFAULT_PORTS_FILE = Path("config/default_ports.yml")
DEFAULT_RISK_RULES_FILE = Path("config/risk_rules.yml")
DEFAULT_OUTPUT_FILE = Path("reports/report.json")


def build_parser():
    """
    Creates and returns the command-line argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="irmapper",
        description=(
            "Internal Reconnaissance Risk Mapper - "
            "a defensive tool for mapping internally exposed services."
        )
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target IP or CIDR subnet, e.g. 192.168.1.10 or 192.168.1.0/24"
    )

    parser.add_argument(
        "--ports",
        default=str(DEFAULT_PORTS_FILE),
        help="Path to the ports configuration YAML file."
    )

    parser.add_argument(
        "--risk-rules",
        default=str(DEFAULT_RISK_RULES_FILE),
        help="Path to the risk rules YAML file."
    )

    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_FILE),
        help="Path where the JSON report will be saved."
    )

    parser.add_argument(
        "--format",
        choices=["json", "html"],
        default="json",
        help="Report format. For now JSON is the main supported format."
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of concurrent scanning threads."
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="TCP connection timeout in seconds."
    )

    return parser


def main():
    """
    Main CLI entry point.

    Coordinates:
    - target parsing
    - config loading
    - port scanning
    - basic terminal output
    """
    parser = build_parser()
    args = parser.parse_args()

    try:
        targets = parse_targets(args.target)
    except ValueError as error:
        parser.error(str(error))

    try:
        ports_config = load_yaml_file(args.ports)
    except (FileNotFoundError, ValueError) as error:
        parser.error(str(error))

    try:
        risk_rules_config = load_yaml_file(args.risk_rules)
    except (FileNotFoundError, ValueError) as error:
        parser.error(str(error))


    ports = ports_config.get("ports", [])

    if not ports:
        parser.error("No ports found in ports configuration file.")

    output_path = Path(args.output)
    ensure_directory_exists(output_path.parent)

    print("Internal Reconnaissance Risk Mapper")
    print("-----------------------------------")
    print(f"Target: {args.target}")
    print(f"Parsed hosts: {len(targets)}")
    print(f"Ports config: {args.ports}")
    print(f"Loaded ports: {len(ports)}")
    print(f"Risk rules config: {args.risk_rules}")
    print(f"Output: {args.output}")
    print(f"Format: {args.format}")
    print(f"Threads: {args.threads}")
    print(f"Timeout: {args.timeout}")
    print()
    print("[+] Starting TCP port scan...")
    print()

    results = scan_targets(
        hosts=targets,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout
    )

    print("[+] Collecting basic service banners...")
    results = add_banners_to_scan_results(results, timeout=args.timeout)

    print("[+] Classifying discovered services...")
    results = classify_scan_results(results)

    print("[+] Calculating risk scores...")
    results = calculate_risk_for_scan_results(results, risk_rules_config)


    hosts_with_open_ports = [
        result for result in results
        if result.get("open_ports")
    ]

    print("[+] Scan completed.")
    print(f"[+] Hosts scanned: {len(results)}")
    print(f"[+] Hosts with open ports: {len(hosts_with_open_ports)}")

    report = build_report(
        target=args.target,
        results=results,
        ports_config_path=args.ports,
        risk_rules_path=args.risk_rules
    )

    save_json_report(report, args.output)
    print(f"[+] JSON report saved to: {args.output}")


    if hosts_with_open_ports:
        print()
        print("--- Open Services ---")

        for result in hosts_with_open_ports:
            print(f"\nHost: {result['host']}")
            print(f"Risk: {result['risk_level']} ({result['risk_score']}/100)")

            for service in result["open_ports"]:
                print(
                    f"  - {service['port']}/tcp "
                    f"{service['service']} "
                    f"({service['category']}, {service['exposure_type']})"
                )

                if service["is_sensitive"]:
                    print("    sensitive: yes")

                if service["is_admin_interface"]:
                    print("    admin interface: possible")

                if service.get("banner"):
                    banner_preview = " ".join(service["banner"].split())[:160]
                    print(f"    banner: {banner_preview}")

            if result.get("findings"):
                print("Findings:")

                for finding in result["findings"]:
                    print(
                        f"  - [{finding['severity']}] "
                        f"{finding['title']} "
                        f"on {finding['port']}/tcp"
                    )
                    print(f"    recommendation: {finding['recommendation']}")
    else:
        print()
        print("No open ports found for the configured port list.")

    print_terminal_summary(report)

