# this checks if service_classifier.py adds exposure_type, is_sensitive, is_admin_interface

from irmapper_core.service_classifier import (
    classify_service,
    classify_host_result,
    classify_scan_results,
)


def test_smb_is_classified_as_sensitive_file_sharing():
    service = {
        "port": 445,
        "service": "SMB",
        "category": "file_sharing",
    }

    result = classify_service(service)

    assert result["port"] == 445
    assert result["service"] == "SMB"
    assert result["category"] == "file_sharing"
    assert result["exposure_type"] == "internal_lateral_movement_risk"
    assert result["is_sensitive"] is True
    assert result["is_admin_interface"] is False


def test_rdp_is_classified_as_remote_administration_risk():
    service = {
        "port": 3389,
        "service": "RDP",
        "category": "remote_access",
    }

    result = classify_service(service)

    assert result["port"] == 3389
    assert result["service"] == "RDP"
    assert result["category"] == "remote_access"
    assert result["exposure_type"] == "remote_administration_risk"
    assert result["is_sensitive"] is False
    assert result["is_admin_interface"] is False


def test_http_alt_is_classified_as_possible_admin_interface():
    service = {
        "port": 8080,
        "service": "HTTP-Alt",
        "category": "web_admin",
    }

    result = classify_service(service)

    assert result["port"] == 8080
    assert result["service"] == "HTTP-Alt"
    assert result["category"] == "web_admin"
    assert result["exposure_type"] == "possible_admin_interface"
    assert result["is_sensitive"] is False
    assert result["is_admin_interface"] is True


def test_unknown_category_gets_unknown_exposure():
    service = {
        "port": 9999,
        "service": "Unknown",
        "category": "unknown",
    }

    result = classify_service(service)

    assert result["exposure_type"] == "unknown_exposure"
    assert result["is_sensitive"] is False
    assert result["is_admin_interface"] is False


def test_classify_host_result_classifies_all_open_ports():
    host_result = {
        "host": "192.168.1.10",
        "open_ports": [
            {
                "port": 445,
                "service": "SMB",
                "category": "file_sharing",
            },
            {
                "port": 8080,
                "service": "HTTP-Alt",
                "category": "web_admin",
            },
        ],
    }

    result = classify_host_result(host_result)

    assert result["host"] == "192.168.1.10"
    assert len(result["open_ports"]) == 2

    assert result["open_ports"][0]["exposure_type"] == "internal_lateral_movement_risk"
    assert result["open_ports"][0]["is_sensitive"] is True

    assert result["open_ports"][1]["exposure_type"] == "possible_admin_interface"
    assert result["open_ports"][1]["is_admin_interface"] is True


def test_classify_scan_results_classifies_multiple_hosts():
    scan_results = [
        {
            "host": "192.168.1.10",
            "open_ports": [
                {
                    "port": 445,
                    "service": "SMB",
                    "category": "file_sharing",
                }
            ],
        },
        {
            "host": "192.168.1.20",
            "open_ports": [
                {
                    "port": 3389,
                    "service": "RDP",
                    "category": "remote_access",
                }
            ],
        },
    ]

    results = classify_scan_results(scan_results)

    assert len(results) == 2
    assert results[0]["open_ports"][0]["exposure_type"] == "internal_lateral_movement_risk"
    assert results[1]["open_ports"][0]["exposure_type"] == "remote_administration_risk"
