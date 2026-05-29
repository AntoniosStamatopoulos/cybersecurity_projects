# this file sets the basic <data structures> of the tool


from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ServiceResult:
    """
    Represents one discovered open service on a host.
    """
    port: int
    service: str
    category: str
    banner: Optional[str] = None
    exposure_type: Optional[str] = None
    is_sensitive: bool = False
    is_admin_interface: bool = False


@dataclass
class Finding:
    """
    Represents one security finding generated from an exposed service.
    """
    title: str
    severity: str
    service: str
    port: int
    category: str
    exposure_type: str
    description: str
    recommendation: str


@dataclass
class HostResult:
    """
    Represents the full result for one scanned host.
    """
    host: str
    open_ports: list[ServiceResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "Low"
    error: Optional[str] = None


@dataclass
class ReportSummary:
    """
    Represents the high-level report summary.
    """
    hosts_scanned: int
    hosts_with_open_ports: int
    high_risk_hosts: int
    medium_risk_hosts: int
    low_risk_hosts: int
    total_findings: int


@dataclass
class ScanReport:
    """
    Represents the complete scan report.
    """
    tool: str
    version: str
    generated_at: str
    target: str
    configuration: dict
    summary: ReportSummary
    results: list[HostResult]