# this test file checks if risk_engine works for risk_score, risK_level, findings, severity

from irmapper_core.risk_engine import (
    calculate_host_risk,
    calculate_risk_for_scan_results,
    get_risk_level,
)


RISK_RULES = {
    "SMB": {
        "severity": "High",
        "score": 25,
        "finding": "SMB file sharing exposure",
        "recommendation": "Restrict SMB access."
    },
    "HTTP": {
        "severity": "Low",
        "score": 5,
        "finding": "Web service exposure",
        "recommendation": "Verify the web service is expected."
    },
    "RDP": {
        "severity": "Medium",
        "score": 20,
        "finding": "RDP remote access exposure",
        "recommendation": "Restrict RDP access."
    },
    "MySQL": {
        "severity": "Medium",
        "score": 15,
        "finding": "MySQL database exposure",
        "recommendation": "Restrict database access."
    },
}


def test_get_risk_level_low():
    assert get_risk_level(0) == "Low"
    assert get_risk_level(30) == "Low"


def test_get_risk_level_medium():
    assert get_risk_level(31) == "Medium"
    assert get_risk_level(69) == "Medium"


def test_get_risk_level_high():
    assert get_risk_level(70) == "High"
    assert get_risk_level(100) == "High"


def test_http_only_gives_low_risk():
    host_result = {
        "host": "192.168.1.10",
        "open_ports": [
            {
                "port": 80,
                "service": "HTTP",
                "category": "web",
                "exposure_type": "web_service_exposure",
            }
        ],
    }

    result = calculate_host_risk(host_result, RISK_RULES)

    assert result["risk_score"] == 5
    assert result["risk_level"] == "Low"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "Low"
    assert result["findings"][0]["title"] == "Web service exposure"


def test_smb_creates_high_severity_finding():
    host_result = {
        "host": "192.168.1.20",
        "open_ports": [
            {
                "port": 445,
                "service": "SMB",
                "category": "file_sharing",
                "exposure_type": "internal_lateral_movement_risk",
            }
        ],
    }

    result = calculate_host_risk(host_result, RISK_RULES)

    assert result["risk_score"] == 25
    assert result["risk_level"] == "Low"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "High"
    assert result["findings"][0]["title"] == "SMB file sharing exposure"


def test_smb_rdp_database_increases_score_to_medium():
    host_result = {
        "host": "192.168.1.30",
        "open_ports": [
            {
                "port": 445,
                "service": "SMB",
                "category": "file_sharing",
                "exposure_type": "internal_lateral_movement_risk",
            },
            {
                "port": 3389,
                "service": "RDP",
                "category": "remote_access",
                "exposure_type": "remote_administration_risk",
            },
            {
                "port": 3306,
                "service": "MySQL",
                "category": "database",
                "exposure_type": "data_exposure_risk",
            },
        ],
    }

    result = calculate_host_risk(host_result, RISK_RULES)

    assert result["risk_score"] == 60
    assert result["risk_level"] == "Medium"
    assert len(result["findings"]) == 3


def test_score_is_capped_at_100():
    host_result = {
        "host": "192.168.1.40",
        "open_ports": [
            {
                "port": 445,
                "service": "SMB",
                "category": "file_sharing",
                "exposure_type": "internal_lateral_movement_risk",
            },
            {
                "port": 445,
                "service": "SMB",
                "category": "file_sharing",
                "exposure_type": "internal_lateral_movement_risk",
            },
            {
                "port": 445,
                "service": "SMB",
                "category": "file_sharing",
                "exposure_type": "internal_lateral_movement_risk",
            },
            {
                "port": 445,
                "service": "SMB",
                "category": "file_sharing",
                "exposure_type": "internal_lateral_movement_risk",
            },
            {
                "port": 445,
                "service": "SMB",
                "category": "file_sharing",
                "exposure_type": "internal_lateral_movement_risk",
            },
        ],
    }

    result = calculate_host_risk(host_result, RISK_RULES)

    assert result["risk_score"] == 100
    assert result["risk_level"] == "High"


def test_calculate_risk_for_scan_results():
    scan_results = [
        {
            "host": "192.168.1.10",
            "open_ports": [
                {
                    "port": 80,
                    "service": "HTTP",
                    "category": "web",
                    "exposure_type": "web_service_exposure",
                }
            ],
        }
    ]

    risk_rules_config = {
        "risk_rules": RISK_RULES
    }

    results = calculate_risk_for_scan_results(scan_results, risk_rules_config)

    assert len(results) == 1
    assert results[0]["risk_score"] == 5
    assert results[0]["risk_level"] == "Low"
    assert len(results[0]["findings"]) == 1