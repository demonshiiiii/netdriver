#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from netdriver_core.nmap.models import ScanResult
from netdriver_core.snmp.client import SNMP_OIDS
from netdriver_core.snmp.models import SnmpCredential
from netdriver_core.snmp.models import SnmpResult
from netdriver_agent.discovery.engine.models import HostResultKey, HostStatus
from netdriver_agent.discovery.engine.worker import DiscoveryTaskWorker
from netdriver_agent.discovery.probe.models import DeviceInfo
from netdriver_agent.discovery.probe.models import DeviceProfile
from netdriver_agent.discovery.probe.models import SshCredential
from netdriver_agent.discovery.probe.models import SshProbeResult


@dataclass
class _FakeTaskStore:
    devices: list[tuple[str, object]]
    host_results: list[dict[str, object]]
    host_logs: list[dict[str, object]]
    statuses: list[tuple[str, object, str]]
    progress_updates: list[tuple[str, int, int]]

    def __init__(self) -> None:
        self.devices = []
        self.host_results = []
        self.host_logs = []
        self.statuses = []
        self.progress_updates = []

    async def add_device(self, task_id: str, device: object) -> None:
        self.devices.append((task_id, device))

    async def set_status(self, task_id: str, status: object, error_message: str = "") -> None:
        self.statuses.append((task_id, status, error_message))

    async def update_progress(self, task_id: str, completed: int, total: int) -> None:
        self.progress_updates.append((task_id, completed, total))

    async def upsert_host_result(self, task_id: str, ip: str, **kwargs: object) -> int:
        record = {"task_id": task_id, "ip": ip, **kwargs}
        self.host_results.append(record)
        return len(self.host_results)

    async def add_host_log(
        self,
        task_id: str,
        ip: str,
        host_result_id: int | None,
        step_code: str,
        step: str,
        status: str,
        message: str = "",
    ) -> None:
        self.host_logs.append(
            {
                "task_id": task_id,
                "ip": ip,
                "host_result_id": host_result_id,
                "step_code": step_code,
                "step": step,
                "status": status,
                "message": message,
            }
        )


@dataclass
class _FakeIdentifier:
    """Placeholder identifier for probe monkeypatches."""


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_and_store_uses_detected_protocol_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    task_store = _FakeTaskStore()
    worker = DiscoveryTaskWorker(task_store=task_store)
    monkeypatch.setattr(worker, "_get_identifier", lambda: _FakeIdentifier())

    captured_ports: dict[str, list[int]] = {"ssh": [], "snmp": []}
    captured_profiles: list[DeviceProfile | None] = []

    async def fake_probe_snmp(
        host: str,
        port: int,
        credentials: list[object],
        identifier: object,
        **_: object,
    ) -> dict[str, str] | None:
        captured_ports["snmp"].append(port)
        return {
            "vendor": "Cisco",
            "model": "N9K",
            "version": "9.3(1)",
            "credential_name": "public-snmp",
            "hostname": "switch-a",
            "community": "public",
            "raw_data": "sysDescr",
        }

    async def fake_probe_ssh(
        host: str,
        port: int,
        credentials: list[SshCredential],
        identifier: object,
        *,
        selection_profile: DeviceProfile | None = None,
        **_: object,
    ) -> dict[str, str] | None:
        captured_ports["ssh"].append(port)
        captured_profiles.append(selection_profile)
        return {
            "vendor": "Cisco",
            "model": "Nexus9000 C93180YC-FX",
            "version": "9.3(1)",
            "credential_name": "admin-ssh",
            "hostname": "switch-a",
            "username": "admin",
            "raw_data": "show version",
        }

    monkeypatch.setattr(worker, "_probe_snmp", fake_probe_snmp)
    monkeypatch.setattr(worker, "_probe_ssh", fake_probe_ssh)

    await worker._probe_and_store(
        task_id="task-123",
        scan_result=ScanResult(
            ip="10.0.0.1",
            has_ssh=True,
            has_snmp=True,
            open_ports=[2222, 1161],
            ssh_ports=[2222],
            snmp_ports=[1161],
        ),
        ssh_credentials=[
            SshCredential(name="admin-ssh", username="admin", password="secret")
        ],
        snmp_credentials=[SnmpCredential(name="public-snmp", community="public")],
    )

    assert captured_ports == {"ssh": [2222], "snmp": [1161]}
    assert len(task_store.devices) == 1
    task_id, device = task_store.devices[0]
    assert task_id == "task-123"
    assert getattr(device, "protocol") == ["SNMP", "SSH"]
    assert getattr(device, "snmp_credential_name") == "public-snmp"
    assert getattr(device, "ssh_credential_name") == "admin-ssh"
    assert getattr(device, "ssh_username") == "admin"
    assert getattr(device, "snmp_community") == "public"
    assert getattr(device, "vendor") == "Cisco"
    assert getattr(device, "model") == "Nexus9000 C93180YC-FX"
    assert getattr(device, "version") == "9.3(1)"
    assert captured_profiles == [
        DeviceProfile(vendor="cisco", model="n9k", version="9.3(1)")
    ]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_and_store_passes_snmp_profile_to_ssh_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    task_store = _FakeTaskStore()
    worker = DiscoveryTaskWorker(task_store=task_store)
    monkeypatch.setattr(worker, "_get_identifier", lambda: _FakeIdentifier())

    captured_profiles: list[DeviceProfile | None] = []

    async def fake_probe_snmp(
        host: str,
        port: int,
        credentials: list[SnmpCredential],
        identifier: object,
        **_: object,
    ) -> dict[str, str] | None:
        return {
            "vendor": "huawei",
            "model": "CE6857",
            "version": "V200R021",
            "hostname": "ce-switch-01",
            "community": credentials[0].community,
            "raw_data": "sysDescr",
        }

    async def fake_probe_ssh(
        host: str,
        port: int,
        credentials: list[SshCredential],
        identifier: object,
        *,
        selection_profile: DeviceProfile | None = None,
        **_: object,
    ) -> dict[str, str] | None:
        captured_profiles.append(selection_profile)
        return {
            "vendor": "huawei",
            "model": "CE6857-48S6CQ-EI",
            "version": "V200R021",
            "hostname": "ce-switch-01",
            "username": credentials[0].username,
            "raw_data": "display version",
        }

    monkeypatch.setattr(worker, "_probe_snmp", fake_probe_snmp)
    monkeypatch.setattr(worker, "_probe_ssh", fake_probe_ssh)

    await worker._probe_and_store(
        task_id="task-snmp-vendor-hint",
        scan_result=ScanResult(
            ip="10.0.0.10",
            has_ssh=True,
            has_snmp=True,
            open_ports=[22, 161],
            ssh_ports=[22],
            snmp_ports=[161],
        ),
        ssh_credentials=[
            SshCredential(name="admin-ssh", username="admin", password="secret")
        ],
        snmp_credentials=[SnmpCredential(name="public-snmp", community="public")],
    )

    assert captured_profiles == [
        DeviceProfile(vendor="huawei", model="ce6857", version="v200r021")
    ]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_and_store_marks_hosts_without_target_ports_as_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    task_store = _FakeTaskStore()
    worker = DiscoveryTaskWorker(task_store=task_store)
    monkeypatch.setattr(worker, "_get_identifier", lambda: _FakeIdentifier())

    await worker._probe_and_store(
        task_id="task-no-target-ports",
        scan_result=ScanResult(ip="10.0.0.99"),
        ssh_credentials=[],
        snmp_credentials=[],
    )

    assert task_store.devices == []
    assert len(task_store.host_results) == 2
    assert task_store.host_results[0]["status"] == HostStatus.SCANNING
    assert task_store.host_results[1]["status"] == HostStatus.PORT_CLOSED
    assert task_store.host_results[1]["result_key"] == HostResultKey.PORT_CLOSED
    assert (
        task_store.host_results[1]["error_message"]
        == "Nmap did not report any configured SNMP or SSH ports for this host; "
        "target ports may be closed or filtered"
    )
    assert any(
        log_item["step_code"] == "port_closed"
        and log_item["message"]
        == "Nmap did not report any configured SNMP or SSH ports for this host; "
        "target ports may be closed or filtered"
        for log_item in task_store.host_logs
    )


@pytest.mark.unit
@pytest.mark.asyncio
async def test_run_counts_hosts_without_target_ports_immediately_after_nmap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    task_store = _FakeTaskStore()
    worker = DiscoveryTaskWorker(task_store=task_store, max_concurrent_probes=1)
    monkeypatch.setattr(worker, "_get_identifier", lambda: _FakeIdentifier())

    async def fake_scan(
        targets: list[str],
        ssh_ports: list[int],
        snmp_ports: list[int],
    ) -> list[ScanResult]:
        assert targets == ["192.168.60.0/24"]
        assert ssh_ports == [22]
        assert snmp_ports == [161]
        return [
            ScanResult(ip="10.0.0.1", has_ssh=True, open_ports=[22], ssh_ports=[22]),
            ScanResult(ip="10.0.0.2"),
            ScanResult(ip="10.0.0.3"),
        ]

    monkeypatch.setattr(worker._nmap_scanner, "scan", fake_scan)

    probe_order: list[str] = []

    async def fake_probe_and_store(
        task_id: str,
        scan_result: ScanResult,
        ssh_credentials: list[SshCredential],
        snmp_credentials: list[SnmpCredential],
    ) -> None:
        probe_order.append(scan_result.ip)

    monkeypatch.setattr(worker, "_probe_and_store", fake_probe_and_store)

    await worker.run(
        task_id="task-priority",
        targets=["192.168.60.0/24"],
        ssh_ports=[22],
        snmp_ports=[161],
        ssh_credentials=[],
        snmp_credentials=[],
    )

    assert probe_order == ["10.0.0.2", "10.0.0.3", "10.0.0.1"]
    assert task_store.progress_updates == [
        ("task-priority", 0, 3),
        ("task-priority", 2, 3),
        ("task-priority", 3, 3),
    ]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_and_store_continues_after_snmp_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    task_store = _FakeTaskStore()
    worker = DiscoveryTaskWorker(task_store=task_store, probe_timeout=0.1)
    monkeypatch.setattr(worker, "_get_identifier", lambda: _FakeIdentifier())

    attempted_communities: list[str] = []

    async def fake_probe_snmp(
        host: str,
        port: int,
        credentials: list[SnmpCredential],
        identifier: object,
        **_: object,
    ) -> dict[str, str] | None:
        community = credentials[0].community
        attempted_communities.append(community)
        if community == "public":
            raise asyncio.TimeoutError

        return {
            "vendor": "Cisco",
            "model": "N9K",
            "version": "9.3(1)",
            "credential_name": credentials[0].name,
            "hostname": "switch-b",
            "community": community,
            "raw_data": "sysDescr",
        }

    monkeypatch.setattr(worker, "_probe_snmp", fake_probe_snmp)

    await worker._probe_and_store(
        task_id="task-456",
        scan_result=ScanResult(
            ip="10.0.0.2",
            has_ssh=False,
            has_snmp=True,
            open_ports=[161],
            ssh_ports=[],
            snmp_ports=[161],
        ),
        ssh_credentials=[],
        snmp_credentials=[
            SnmpCredential(name="public-snmp", community="public"),
            SnmpCredential(name="private-snmp", community="private"),
        ],
    )

    assert attempted_communities == ["public", "private"]
    assert len(task_store.devices) == 1
    task_id, device = task_store.devices[0]
    assert task_id == "task-456"
    assert getattr(device, "method") == "snmp"
    assert getattr(device, "snmp_credential_name") == "private-snmp"
    assert getattr(device, "snmp_community") == "private"
    auth_logs = [log for log in task_store.host_logs if log["step_code"] == "snmp_auth"]
    assert auth_logs == [
        {
            "task_id": "task-456",
            "ip": "10.0.0.2",
            "host_result_id": 1,
            "step_code": "snmp_auth",
            "step": "SNMP authentication",
            "status": "Success",
            "message": "SNMP authentication succeeded with credential 'private-snmp' on port 161",
        }
    ]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_and_store_continues_after_ssh_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    task_store = _FakeTaskStore()
    worker = DiscoveryTaskWorker(task_store=task_store, probe_timeout=0.1)
    monkeypatch.setattr(worker, "_get_identifier", lambda: _FakeIdentifier())

    attempted_users: list[str] = []

    async def fake_probe_ssh(
        host: str,
        port: int,
        credentials: list[SshCredential],
        identifier: object,
        *,
        selection_profile: DeviceProfile | None = None,
        **_: object,
    ) -> dict[str, str] | None:
        username = credentials[0].username
        attempted_users.append(username)
        if username == "admin":
            raise asyncio.TimeoutError

        return {
            "vendor": "Cisco",
            "model": "N9K",
            "version": "9.3(1)",
            "credential_name": credentials[0].name,
            "hostname": "switch-c",
            "username": username,
            "raw_data": "show version",
        }

    monkeypatch.setattr(worker, "_probe_ssh", fake_probe_ssh)

    await worker._probe_and_store(
        task_id="task-789",
        scan_result=ScanResult(
            ip="10.0.0.3",
            has_ssh=True,
            has_snmp=False,
            open_ports=[22],
            ssh_ports=[22],
            snmp_ports=[],
        ),
        ssh_credentials=[
            SshCredential(name="admin-ssh", username="admin", password="secret"),
            SshCredential(name="ops-ssh", username="ops", password="secret"),
        ],
        snmp_credentials=[],
    )

    assert attempted_users == ["admin", "ops"]
    assert len(task_store.devices) == 1
    task_id, device = task_store.devices[0]
    assert task_id == "task-789"
    assert getattr(device, "method") == "ssh"
    assert getattr(device, "ssh_credential_name") == "ops-ssh"
    assert getattr(device, "ssh_username") == "ops"
    auth_logs = [log for log in task_store.host_logs if log["step_code"] == "ssh_auth"]
    assert auth_logs == [
        {
            "task_id": "task-789",
            "ip": "10.0.0.3",
            "host_result_id": 1,
            "step_code": "ssh_auth",
            "step": "SSH authentication",
            "status": "Success",
            "message": "SSH authentication succeeded with credential 'ops-ssh' on port 22",
        }
    ]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_and_store_marks_ssh_connect_timeout_as_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    task_store = _FakeTaskStore()
    worker = DiscoveryTaskWorker(task_store=task_store)
    monkeypatch.setattr(worker, "_get_identifier", lambda: _FakeIdentifier())

    async def fake_probe_ssh(
        host: str,
        port: int,
        credentials: list[SshCredential],
        identifier: object,
        *,
        selection_profile: DeviceProfile | None = None,
        **_: object,
    ) -> str:
        return "timeout"

    monkeypatch.setattr(worker, "_probe_ssh", fake_probe_ssh)

    await worker._probe_and_store(
        task_id="task-ssh-timeout",
        scan_result=ScanResult(
            ip="10.0.0.30",
            has_ssh=True,
            has_snmp=False,
            open_ports=[22],
            ssh_ports=[22],
            snmp_ports=[],
        ),
        ssh_credentials=[
            SshCredential(name="admin-ssh", username="admin", password="secret"),
        ],
        snmp_credentials=[],
    )

    assert task_store.host_results[-1]["status"] == HostStatus.TIMEOUT
    assert task_store.host_results[-1]["result_key"] == HostResultKey.TIMEOUT
    auth_logs = [log for log in task_store.host_logs if log["step_code"] == "ssh_auth"]
    assert auth_logs == [
        {
            "task_id": "task-ssh-timeout",
            "ip": "10.0.0.30",
            "host_result_id": 1,
            "step_code": "ssh_auth",
            "step": "SSH authentication",
            "status": "Failed",
            "message": "All SSH credentials timed out on port 22 after 1 attempt(s)",
        }
    ]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_and_store_records_single_failed_ssh_auth_log_when_all_credentials_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    task_store = _FakeTaskStore()
    worker = DiscoveryTaskWorker(task_store=task_store)
    monkeypatch.setattr(worker, "_get_identifier", lambda: _FakeIdentifier())

    async def fake_probe_ssh(
        host: str,
        port: int,
        credentials: list[SshCredential],
        identifier: object,
        *,
        selection_profile: DeviceProfile | None = None,
        **_: object,
    ) -> dict[str, str] | None:
        return None

    monkeypatch.setattr(worker, "_probe_ssh", fake_probe_ssh)

    await worker._probe_and_store(
        task_id="task-ssh-all-failed",
        scan_result=ScanResult(
            ip="10.0.0.30",
            has_ssh=True,
            has_snmp=False,
            open_ports=[22],
            ssh_ports=[22],
            snmp_ports=[],
        ),
        ssh_credentials=[
            SshCredential(name="admin-ssh", username="admin", password="secret"),
            SshCredential(name="ops-ssh", username="ops", password="secret"),
        ],
        snmp_credentials=[],
    )

    auth_logs = [log for log in task_store.host_logs if log["step_code"] == "ssh_auth"]
    assert auth_logs == [
        {
            "task_id": "task-ssh-all-failed",
            "ip": "10.0.0.30",
            "host_result_id": 1,
            "step_code": "ssh_auth",
            "step": "SSH authentication",
            "status": "Failed",
            "message": "All SSH credentials failed authentication on port 22 after 2 attempt(s)",
        }
    ]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_and_store_records_single_failed_snmp_auth_log_when_all_credentials_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    task_store = _FakeTaskStore()
    worker = DiscoveryTaskWorker(task_store=task_store)
    monkeypatch.setattr(worker, "_get_identifier", lambda: _FakeIdentifier())

    async def fake_probe_snmp(
        host: str,
        port: int,
        credentials: list[SnmpCredential],
        identifier: object,
        **_: object,
    ) -> dict[str, str] | None:
        return None

    monkeypatch.setattr(worker, "_probe_snmp", fake_probe_snmp)

    await worker._probe_and_store(
        task_id="task-snmp-all-failed",
        scan_result=ScanResult(
            ip="10.0.0.31",
            has_ssh=False,
            has_snmp=True,
            open_ports=[161],
            ssh_ports=[],
            snmp_ports=[161],
        ),
        ssh_credentials=[],
        snmp_credentials=[
            SnmpCredential(name="public-snmp", community="public"),
            SnmpCredential(name="private-snmp", community="private"),
        ],
    )

    auth_logs = [log for log in task_store.host_logs if log["step_code"] == "snmp_auth"]
    assert auth_logs == [
        {
            "task_id": "task-snmp-all-failed",
            "ip": "10.0.0.31",
            "host_result_id": 1,
            "step_code": "snmp_auth",
            "step": "SNMP authentication",
            "status": "Failed",
            "message": "All SNMP credentials failed authentication on port 161 after 2 attempt(s)",
        }
    ]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_and_store_marks_inconclusive_ssh_identification_without_fake_detection_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    task_store = _FakeTaskStore()
    worker = DiscoveryTaskWorker(task_store=task_store)
    monkeypatch.setattr(worker, "_get_identifier", lambda: _FakeIdentifier())

    async def fake_probe_ssh(
        host: str,
        port: int,
        credentials: list[SshCredential],
        identifier: object,
        *,
        selection_profile: DeviceProfile | None = None,
        **_: object,
    ) -> dict[str, str] | None:
        return {
            "vendor": "",
            "model": "",
            "version": "",
            "credential_name": credentials[0].name,
            "hostname": "",
            "username": credentials[0].username,
            "raw_data": "login banner",
        }

    monkeypatch.setattr(worker, "_probe_ssh", fake_probe_ssh)

    await worker._probe_and_store(
        task_id="task-inconclusive-ssh",
        scan_result=ScanResult(
            ip="10.0.0.4",
            has_ssh=True,
            has_snmp=False,
            open_ports=[22],
            ssh_ports=[22],
            snmp_ports=[],
        ),
        ssh_credentials=[
            SshCredential(name="ops-ssh", username="ops", password="secret"),
        ],
        snmp_credentials=[],
    )

    assert len(task_store.devices) == 1
    _, device = task_store.devices[0]
    assert getattr(device, "method") == "ssh"
    assert getattr(device, "ssh_credential_name") == "ops-ssh"
    assert getattr(device, "vendor") == ""

    vendor_logs = [
        log for log in task_store.host_logs if log["step_code"] == "ssh_vendor_detect"
    ]
    completion_logs = [
        log for log in task_store.host_logs if log["step_code"] == "completed"
    ]

    assert vendor_logs == [
        {
            "task_id": "task-inconclusive-ssh",
            "ip": "10.0.0.4",
            "host_result_id": 1,
            "step_code": "ssh_vendor_detect",
            "step": "SSH vendor detection",
            "status": "Skipped",
            "message": "SSH probe succeeded but device identification was inconclusive",
        }
    ]
    assert completion_logs == [
        {
            "task_id": "task-inconclusive-ssh",
            "ip": "10.0.0.4",
            "host_result_id": 1,
            "step_code": "completed",
            "step": "Scan completed",
            "status": "Success",
            "message": "SSH access succeeded but device identification was inconclusive",
        }
    ]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_ssh_passes_selection_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    worker = DiscoveryTaskWorker(task_store=_FakeTaskStore())
    captured_profiles: list[DeviceProfile | None] = []

    class _FakeProbe:
        async def probe(
            self,
            host: str,
            port: int,
            credentials: list[SshCredential],
            identifier: object,
            connect_timeout: float = 10.0,
            read_timeout: float = 5.0,
            selection_profile: DeviceProfile | None = None,
            event_logger: object | None = None,
        ) -> SshProbeResult:
            captured_profiles.append(selection_profile)
            return SshProbeResult(
                success=True,
                host=host,
                port=port,
                credential=credentials[0],
                device_info=DeviceInfo(
                    vendor="huawei",
                    model="CE6857-48S6CQ-EI",
                    version="V200R021",
                ),
                raw_output="display version",
            )

    monkeypatch.setattr(
        "netdriver_agent.discovery.engine.worker.SshProbe",
        lambda: _FakeProbe(),
    )

    result = await worker._probe_ssh(
        host="10.0.0.20",
        port=22,
        credentials=[SshCredential(name="ops-ssh", username="ops", password="secret")],
        identifier=_FakeIdentifier(),
        selection_profile=DeviceProfile(vendor="huawei", model="ce6857", version="v200r021"),
    )

    assert captured_profiles == [
        DeviceProfile(vendor="huawei", model="ce6857", version="v200r021")
    ]
    assert result == {
        "vendor": "huawei",
        "model": "CE6857-48S6CQ-EI",
        "version": "V200R021",
        "hostname": "",
        "device_type": "",
        "serial_number": "",
        "credential_name": "ops-ssh",
        "username": "ops",
        "raw_data": "display version",
    }


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_and_store_keeps_snmp_vendor_when_ssh_vendor_conflicts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    task_store = _FakeTaskStore()
    worker = DiscoveryTaskWorker(task_store=task_store)
    monkeypatch.setattr(worker, "_get_identifier", lambda: _FakeIdentifier())

    async def fake_probe_snmp(
        host: str,
        port: int,
        credentials: list[SnmpCredential],
        identifier: object,
        **_: object,
    ) -> dict[str, str] | None:
        return {
            "vendor": "huawei",
            "model": "CE6857",
            "version": "V200R019",
            "credential_name": credentials[0].name,
            "hostname": "ce-switch-02",
            "community": credentials[0].community,
            "raw_data": "sysDescr",
        }

    async def fake_probe_ssh(
        host: str,
        port: int,
        credentials: list[SshCredential],
        identifier: object,
        *,
        selection_profile: DeviceProfile | None = None,
        **_: object,
    ) -> dict[str, str] | None:
        return {
            "vendor": "h3c",
            "model": "CE6857-48S6CQ-EI",
            "version": "V200R021C10SPC600",
            "credential_name": credentials[0].name,
            "hostname": "ce-switch-02",
            "username": credentials[0].username,
            "raw_data": "display version",
        }

    monkeypatch.setattr(worker, "_probe_snmp", fake_probe_snmp)
    monkeypatch.setattr(worker, "_probe_ssh", fake_probe_ssh)

    await worker._probe_and_store(
        task_id="task-merge-001",
        scan_result=ScanResult(
            ip="10.0.0.21",
            has_ssh=True,
            has_snmp=True,
            open_ports=[22, 161],
            ssh_ports=[22],
            snmp_ports=[161],
        ),
        ssh_credentials=[SshCredential(name="ops-ssh", username="ops", password="secret")],
        snmp_credentials=[SnmpCredential(name="public-snmp", community="public")],
    )

    _, device = task_store.devices[0]
    assert getattr(device, "vendor") == "huawei"
    assert getattr(device, "model") == "CE6857-48S6CQ-EI"
    assert getattr(device, "version") == "V200R021C10SPC600"
    assert getattr(device, "protocol") == ["SNMP", "SSH"]
    assert getattr(device, "snmp_credential_name") == "public-snmp"
    assert getattr(device, "ssh_credential_name") == "ops-ssh"
    assert getattr(device, "raw_data") == "[SNMP]\nsysDescr\n\n[SSH]\ndisplay version"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_and_store_applies_ingest_rules_to_final_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    task_store = _FakeTaskStore()
    worker = DiscoveryTaskWorker(task_store=task_store)
    monkeypatch.setattr(worker, "_get_identifier", lambda: _FakeIdentifier())

    async def fake_probe_snmp(
        host: str,
        port: int,
        credentials: list[SnmpCredential],
        identifier: object,
        **_: object,
    ) -> dict[str, str] | None:
        return {
            "vendor": "cisco",
            "model": "n9k",
            "version": "17.9",
            "device_type": "switch",
            "credential_name": credentials[0].name,
            "hostname": "edge-sw-03",
            "community": credentials[0].community,
            "raw_data": "sysDescr",
        }

    monkeypatch.setattr(worker, "_probe_snmp", fake_probe_snmp)
    monkeypatch.setattr(
        "netdriver_agent.discovery.engine.worker.apply_ingest_rules",
        lambda values: {
            **values,
            "vendor": "Cisco",
            "model": "N9K",
            "device_type": "Switch",
        },
    )

    await worker._probe_and_store(
        task_id="task-ingest-001",
        scan_result=ScanResult(
            ip="10.0.0.22",
            has_ssh=False,
            has_snmp=True,
            open_ports=[161],
            ssh_ports=[],
            snmp_ports=[161],
        ),
        ssh_credentials=[],
        snmp_credentials=[SnmpCredential(name="public-snmp", community="public")],
    )

    _, device = task_store.devices[0]
    assert getattr(device, "vendor") == "Cisco"
    assert getattr(device, "model") == "N9K"
    assert getattr(device, "version") == "17.9"
    assert getattr(device, "device_type") == "Switch"
    assert task_store.host_results[-1]["vendor"] == "Cisco"
    assert task_store.host_results[-1]["model"] == "N9K"
    assert task_store.host_results[-1]["device_type"] == "Switch"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_snmp_identifies_vendor_by_oid_then_fetches_detail_oids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    worker = DiscoveryTaskWorker(task_store=_FakeTaskStore())
    detail_oids = {
        "model": ["1.3.6.1.4.1.9.9.1.1.0"],
        "version": ["1.3.6.1.4.1.9.9.1.2.0"],
        "serial_number": ["1.3.6.1.4.1.9.9.1.3.0"],
    }
    monkeypatch.setattr(
        "netdriver_agent.discovery.engine.worker.get_vendor_snmp_detail_oids",
        lambda vendor: detail_oids,
    )

    class _FakeSnmpClient:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        async def get(
            self,
            host: str,
            credential: SnmpCredential,
            oids: list[str],
            port: int | None = None,
        ) -> SnmpResult:
            self.calls.append(oids)
            if oids == [
                SNMP_OIDS["sysDescr"],
                SNMP_OIDS["sysObjectID"],
                SNMP_OIDS["sysName"],
            ]:
                return SnmpResult(
                    success=True,
                    data={
                        SNMP_OIDS["sysDescr"]: "Cisco IOS XE Software, Version 17.9.4",
                        SNMP_OIDS["sysObjectID"]: "1.3.6.1.4.1.2011.2.23.221",
                        SNMP_OIDS["sysName"]: "edge-sw-01",
                    },
                )

            if oids == detail_oids["model"] + detail_oids["version"] + detail_oids["serial_number"]:
                return SnmpResult(
                    success=True,
                    data={
                        detail_oids["model"][0]: "C9300-48P",
                        detail_oids["version"][0]: "17.9.4a",
                    },
                )

            return SnmpResult(success=False, error="unexpected oids")

    class _FakeIdentifier:
        def identify_by_oid(self, sys_object_id: str) -> str | None:
            assert sys_object_id == "1.3.6.1.4.1.2011.2.23.221"
            return "cisco"

    worker._snmp_client = _FakeSnmpClient()

    result = await worker._probe_snmp(
        host="10.0.0.10",
        port=161,
        credentials=[SnmpCredential(name="dc-snmp", community="public")],
        identifier=_FakeIdentifier(),
    )

    assert result == {
        "vendor": "cisco",
        "model": "C9300-48P",
        "version": "17.9.4a",
        "device_type": "",
        "serial_number": "",
        "credential_name": "dc-snmp",
        "hostname": "edge-sw-01",
        "community": "public",
        "raw_data": "Cisco IOS XE Software, Version 17.9.4",
    }
    assert worker._snmp_client.calls == [
        [
            SNMP_OIDS["sysDescr"],
            SNMP_OIDS["sysObjectID"],
            SNMP_OIDS["sysName"],
        ],
        detail_oids["model"] + detail_oids["version"] + detail_oids["serial_number"],
    ]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_snmp_returns_empty_model_and_version_when_detail_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    worker = DiscoveryTaskWorker(task_store=_FakeTaskStore())
    monkeypatch.setattr(
        "netdriver_agent.discovery.engine.worker.get_vendor_snmp_detail_oids",
        lambda vendor: {
            "model": ["1.3.6.1.4.1.9.9.1.1.0"],
            "version": ["1.3.6.1.4.1.9.9.1.2.0"],
        },
    )

    class _FakeSnmpClient:
        async def get(
            self,
            host: str,
            credential: SnmpCredential,
            oids: list[str],
            port: int | None = None,
        ) -> SnmpResult:
            if oids == [
                SNMP_OIDS["sysDescr"],
                SNMP_OIDS["sysObjectID"],
                SNMP_OIDS["sysName"],
            ]:
                return SnmpResult(
                    success=True,
                    data={
                        SNMP_OIDS["sysDescr"]: "Cisco NX-OS(tm) Software, Version 9.3(8)",
                        SNMP_OIDS["sysObjectID"]: "1.3.6.1.4.1.9.12.3.1.3.1931",
                        SNMP_OIDS["sysName"]: "n9k-01",
                    },
                )

            return SnmpResult(success=False, error="detail oids unsupported")

    class _FakeIdentifier:
        def identify_by_oid(self, sys_object_id: str) -> str | None:
            assert sys_object_id == "1.3.6.1.4.1.9.12.3.1.3.1931"
            return "cisco"

    worker._snmp_client = _FakeSnmpClient()

    result = await worker._probe_snmp(
        host="10.0.0.11",
        port=161,
        credentials=[SnmpCredential(name="dc-snmp", community="public")],
        identifier=_FakeIdentifier(),
    )

    assert result == {
        "vendor": "cisco",
        "model": "",
        "version": "",
        "device_type": "",
        "serial_number": "",
        "credential_name": "dc-snmp",
        "hostname": "n9k-01",
        "community": "public",
        "raw_data": "Cisco NX-OS(tm) Software, Version 9.3(8)",
    }


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_snmp_skips_detail_lookup_when_vendor_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    worker = DiscoveryTaskWorker(task_store=_FakeTaskStore())
    monkeypatch.setattr(
        "netdriver_agent.discovery.engine.worker.get_vendor_snmp_detail_oids",
        lambda vendor: {
            "model": ["1.3.6.1.4.1.9.9.1.1.0"],
        },
    )

    class _FakeSnmpClient:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        async def get(
            self,
            host: str,
            credential: SnmpCredential,
            oids: list[str],
            port: int | None = None,
        ) -> SnmpResult:
            self.calls.append(oids)
            return SnmpResult(
                success=True,
                data={
                    SNMP_OIDS["sysDescr"]: "Unknown device",
                    SNMP_OIDS["sysObjectID"]: "1.3.6.1.4.1.65528.1.2",
                    SNMP_OIDS["sysName"]: "unknown-01",
                },
            )

    class _FakeIdentifier:
        def identify_by_oid(self, sys_object_id: str) -> str | None:
            assert sys_object_id == "1.3.6.1.4.1.65528.1.2"
            return None

    worker._snmp_client = _FakeSnmpClient()

    result = await worker._probe_snmp(
        host="10.0.0.12",
        port=161,
        credentials=[SnmpCredential(name="dc-snmp", community="public")],
        identifier=_FakeIdentifier(),
    )

    assert result == {
        "vendor": "",
        "model": "",
        "version": "",
        "device_type": "",
        "serial_number": "",
        "credential_name": "dc-snmp",
        "hostname": "unknown-01",
        "community": "public",
        "raw_data": "Unknown device",
    }
    assert worker._snmp_client.calls == [
        [
            SNMP_OIDS["sysDescr"],
            SNMP_OIDS["sysObjectID"],
            SNMP_OIDS["sysName"],
        ],
    ]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_snmp_uses_first_non_empty_detail_oid_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DiscoveryTaskWorker, "_load_vendor_probes", lambda self: None)
    monkeypatch.setattr(
        "netdriver_core.nmap.scanner.NmapScanner._verify_nmap",
        lambda self: None,
    )

    worker = DiscoveryTaskWorker(task_store=_FakeTaskStore())
    detail_oids = {
        "model": [
            "1.3.6.1.4.1.9.9.1.1.0",
            "1.3.6.1.4.1.9.9.1.1.1",
        ],
        "version": [
            "1.3.6.1.4.1.9.9.1.2.0",
            "1.3.6.1.4.1.9.9.1.2.1",
        ],
    }
    monkeypatch.setattr(
        "netdriver_agent.discovery.engine.worker.get_vendor_snmp_detail_oids",
        lambda vendor: detail_oids,
    )

    class _FakeSnmpClient:
        async def get(
            self,
            host: str,
            credential: SnmpCredential,
            oids: list[str],
            port: int | None = None,
        ) -> SnmpResult:
            if oids == [
                SNMP_OIDS["sysDescr"],
                SNMP_OIDS["sysObjectID"],
                SNMP_OIDS["sysName"],
            ]:
                return SnmpResult(
                    success=True,
                    data={
                        SNMP_OIDS["sysDescr"]: "Cisco IOS XE Software",
                        SNMP_OIDS["sysObjectID"]: "1.3.6.1.4.1.9.1.1208",
                        SNMP_OIDS["sysName"]: "edge-sw-02",
                    },
                )

            return SnmpResult(
                success=True,
                data={
                    detail_oids["model"][0]: "",
                    detail_oids["model"][1]: "C9500-24Y4C",
                    detail_oids["version"][0]: "",
                    detail_oids["version"][1]: "17.12.1",
                },
            )

    class _FakeIdentifier:
        def identify_by_oid(self, sys_object_id: str) -> str | None:
            assert sys_object_id == "1.3.6.1.4.1.9.1.1208"
            return "cisco"

    worker._snmp_client = _FakeSnmpClient()

    result = await worker._probe_snmp(
        host="10.0.0.13",
        port=161,
        credentials=[SnmpCredential(name="dc-snmp", community="public")],
        identifier=_FakeIdentifier(),
    )

    assert result == {
        "vendor": "cisco",
        "model": "C9500-24Y4C",
        "version": "17.12.1",
        "device_type": "",
        "serial_number": "",
        "credential_name": "dc-snmp",
        "hostname": "edge-sw-02",
        "community": "public",
        "raw_data": "Cisco IOS XE Software",
    }
