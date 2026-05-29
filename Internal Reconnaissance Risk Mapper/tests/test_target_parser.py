#this checks if target_parser.py works (software testing)


import pytest

from irmapper_core.target_parser import parse_targets


def test_parse_single_ip():
    """
    A single valid IP address should return a list with one item.
    """
    result = parse_targets("192.168.1.10")

    assert result == ["192.168.1.10"]


def test_parse_cidr_subnet():
    """
    A CIDR subnet should return all usable host IP addresses.
    """
    result = parse_targets("192.168.1.0/30")

    assert result == [
        "192.168.1.1",
        "192.168.1.2",
    ]


def test_parse_localhost():
    """
    Localhost should be accepted as a valid single IP.
    """
    result = parse_targets("127.0.0.1")

    assert result == ["127.0.0.1"]


def test_parse_invalid_target():
    """
    Invalid input should raise ValueError.
    """
    with pytest.raises(ValueError):
        parse_targets("hello")


def test_parse_empty_target():
    """
    Empty input should raise ValueError.
    """
    with pytest.raises(ValueError):
        parse_targets("")