#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any

import pytest

from netdriver_core.exception.errors import DiscoveryScanFailed
from netdriver_core.nmap.models import ScanResult
from netdriver_core.nmap.scanner import (
    DEFAULT_SNMP_PORTS,
    DEFAULT_SSH_PORTS,
    NmapScanner,
)


def _build_scanner(monkeypatch: pytest.MonkeyPatch) -> NmapScanner:
    monkeypatch.setattr(NmapScanner, "_verify_nmap", lambda self: None)
    return NmapScanner()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_scan_uses_default_ports_when_ports_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _build_scanner(monkeypatch)
    captured: dict[str, Any] = {}

    async def fake_scan_ports(
        targets: list[str],
        ssh_ports: list[int] | None = None,
        snmp_ports: list[int] | None = None,
    ) -> list[ScanResult]:
        captured["targets"] = targets
        captured["ssh_ports"] = ssh_ports
        captured["snmp_ports"] = snmp_ports
        return []

    monkeypatch.setattr(scanner, "scan_ports", fake_scan_ports)

    await scanner.scan(["10.0.0.0/24"])

    assert captured == {
        "targets": ["10.0.0.0/24"],
        "ssh_ports": DEFAULT_SSH_PORTS,
        "snmp_ports": DEFAULT_SNMP_PORTS,
    }


@pytest.mark.unit
@pytest.mark.asyncio
async def test_scan_ports_returns_hosts_with_and_without_matching_target_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _build_scanner(monkeypatch)

    def fake_run_port_scan(
        target: str,
        ssh_ports: list[int],
        snmp_ports: list[int],
    ) -> dict[str, dict[str, Any]]:
        assert target == "192.168.1.10 192.168.1.11 192.168.1.12"
        assert ssh_ports == [22]
        assert snmp_ports == [161]
        return {
            "192.168.1.10": {
                "tcp": {
                    22: {"state": "open"},
                    161: {"state": "closed"},
                },
            },
            "192.168.1.11": {
                "udp": {
                    161: {"state": "open|filtered"},
                },
            },
            "192.168.1.12": {
                "tcp": {
                    22: {"state": "closed"},
                },
                "udp": {
                    161: {"state": "closed"},
                },
            },
        }

    monkeypatch.setattr(scanner, "_run_port_scan", fake_run_port_scan)

    results = await scanner.scan_ports(
        ["192.168.1.10", "192.168.1.11", "192.168.1.12"],
        ssh_ports=[22],
        snmp_ports=[161],
    )

    assert results == [
        ScanResult(
            ip="192.168.1.10",
            has_ssh=True,
            open_ports=[22],
            ssh_ports=[22],
        ),
        ScanResult(
            ip="192.168.1.11",
            has_snmp=True,
            open_ports=[161],
            snmp_ports=[161],
        ),
        ScanResult(
            ip="192.168.1.12",
        ),
    ]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_scan_ports_fills_missing_targets_not_returned_by_nmap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _build_scanner(monkeypatch)

    def fake_run_port_scan(
        target: str,
        ssh_ports: list[int],
        snmp_ports: list[int],
    ) -> dict[str, dict[str, Any]]:
        assert target == "192.168.1.10 192.168.1.11 192.168.1.12"
        assert ssh_ports == [22]
        assert snmp_ports == [161]
        return {
            "192.168.1.10": {
                "tcp": {
                    22: {"state": "open"},
                },
            },
        }

    monkeypatch.setattr(scanner, "_run_port_scan", fake_run_port_scan)

    results = await scanner.scan_ports(
        ["192.168.1.10", "192.168.1.11", "192.168.1.12"],
        ssh_ports=[22],
        snmp_ports=[161],
    )

    assert results == [
        ScanResult(
            ip="192.168.1.10",
            has_ssh=True,
            open_ports=[22],
            ssh_ports=[22],
        ),
        ScanResult(ip="192.168.1.11"),
        ScanResult(ip="192.168.1.12"),
    ]


@pytest.mark.unit
def test_expand_targets_supports_cidr_range_and_dedup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _build_scanner(monkeypatch)

    expanded = scanner._expand_targets(
        [
            "192.168.1.0/30",
            "192.168.1.2-192.168.1.4",
            "192.168.1.4",
            "10.0.0.1-3",
        ]
    )

    assert expanded == [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
        "192.168.1.4",
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    ]


@pytest.mark.unit
def test_expand_targets_rejects_descending_short_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _build_scanner(monkeypatch)

    with pytest.raises(ValueError, match="invalid IP range: 10.0.0.10-1"):
        scanner._expand_targets(["10.0.0.10-1"])


@pytest.mark.unit
@pytest.mark.asyncio
async def test_scan_ports_wraps_scan_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _build_scanner(monkeypatch)

    def fake_run_port_scan(
        _: str,
        __: list[int],
        ___: list[int],
    ) -> dict[str, dict[str, Any]]:
        raise RuntimeError("boom")

    monkeypatch.setattr(scanner, "_run_port_scan", fake_run_port_scan)

    with pytest.raises(DiscoveryScanFailed, match="Port scan failed: boom"):
        await scanner.scan_ports(["192.168.1.10"], ssh_ports=[22], snmp_ports=[])


@pytest.mark.unit
def test_run_port_scan_builds_protocol_aware_nmap_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _build_scanner(monkeypatch)
    captured: dict[str, object] = {}

    class _FakePortScanner:
        def __init__(self, nmap_search_path: tuple[str, ...]) -> None:
            captured["nmap_search_path"] = nmap_search_path

        def scan(self, hosts: str, arguments: str) -> None:
            captured["hosts"] = hosts
            captured["arguments"] = arguments

        def all_hosts(self) -> list[str]:
            return []

    monkeypatch.setattr("netdriver_core.nmap.scanner.nmap.PortScanner", _FakePortScanner)
    monkeypatch.setattr("netdriver_core.nmap.scanner.os.geteuid", lambda: 0)

    scanner._run_port_scan("192.168.60.0/24", [22], [161])

    assert captured["nmap_search_path"] == ("nmap",)
    assert captured["hosts"] == "192.168.60.0/24"
    assert captured["arguments"] == (
        "-sS -sU -sV --version-intensity 0 -T4 "
        "-p T:22,U:161 --max-retries 2 --host-timeout 30s"
    )
