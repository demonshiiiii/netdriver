#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable
from typing import Any, cast

import pytest

from netdriver_agent.discovery.engine.discovery_engine import DiscoveryEngine
from netdriver_agent.discovery.engine.models import (
    DiscoveredDevice,
    DiscoveryHostLog,
    DiscoveryHostResult,
    DiscoveryTask,
    TaskStatus,
)
from netdriver_agent.discovery.engine.task_store import TaskStore

from netdriver_agent.handlers.discovery_handler import DiscoveryRequestHandler
from netdriver_agent.models.discovery import (
    DiscoveryPortsModel,
    DiscoveryRequest,
    SnmpCollectRequest,
    SnmpCredentialModel,
    SshCredentialModel,
)
from netdriver_core.snmp.client import SnmpClient
from netdriver_core.snmp.models import SnmpResult


@dataclass
class _FakeEngine:
    captured: dict[str, Any]

    def __init__(self) -> None:
        self.captured = {}

    async def start_discovery(self, **kwargs: Any) -> str:
        self.captured = kwargs
        return "task-123"

    async def cancel_task(self, task_id: str) -> bool:
        return task_id == "task-123"


@dataclass
class _FakeTaskStore:
    task: DiscoveryTask | None = None
    hosts: list[DiscoveryHostResult] | None = None
    logs: list[DiscoveryHostLog] | None = None

    async def count_running_tasks(self) -> int:
        return 0

    async def get_task(
        self,
        task_id: str,
    ) -> DiscoveryTask | None:
        if self.task and self.task.id == task_id:
            return self.task
        return None

    async def list_tasks(self) -> list[DiscoveryTask]:
        return [self.task] if self.task else []

    async def list_host_results(
        self,
        task_id: str,
        include_logs: bool = False,
    ) -> list[DiscoveryHostResult]:
        assert self.task is not None
        assert self.task.id == task_id
        return self.hosts or []

    async def list_host_logs(self, task_id: str, ip: str) -> list[DiscoveryHostLog]:
        assert self.task is not None
        assert self.task.id == task_id
        return [log for log in (self.logs or []) if log.ip == ip]


@dataclass
class _FakeSnmpClient:
    timeout: float
    retries: int
    response: SnmpResult
    captured: dict[str, Any]

    def __init__(self, timeout: float, retries: int) -> None:
        self.timeout = timeout
        self.retries = retries
        self.response = SnmpResult(success=True, data={"1.3.6.1.2.1.1.1.0": "sysDescr"})
        self.captured = {}

    async def get(
        self,
        host: str,
        credential,
        oids: list[str],
        port: int | None = None,
    ) -> SnmpResult:
        self.captured = {
            "host": host,
            "credential": credential,
            "oids": oids,
            "port": port,
        }
        return self.response


@pytest.mark.unit
@pytest.mark.asyncio
async def test_start_discovery_passes_request_overrides_to_engine() -> None:
    engine = _FakeEngine()
    task_store = _FakeTaskStore()
    handler = DiscoveryRequestHandler(
        engine=cast(DiscoveryEngine, engine),
        task_store=cast(TaskStore, task_store),
    )

    response = await handler.start_discovery(
        DiscoveryRequest(
            targets=["10.0.0.0/24"],
            ports=DiscoveryPortsModel(ssh=[22], snmp=[161]),
            ssh_credentials=[
                SshCredentialModel(
                    name="ops-ssh",
                    username="admin",
                    password="secret",
                )
            ],
            snmp_credentials=[SnmpCredentialModel(name="dc-snmp", community="public")],
            max_concurrent_probes=88,
            probe_timeout=9.5,
        )
    )

    assert response.task_id == "task-123"
    assert engine.captured["targets"] == ["10.0.0.0/24"]
    assert engine.captured["ssh_ports"] == [22]
    assert engine.captured["snmp_ports"] == [161]
    assert engine.captured["max_concurrent_probes"] == 88
    assert engine.captured["probe_timeout"] == 9.5
    assert engine.captured["ssh_credentials"][0].name == "ops-ssh"
    assert engine.captured["snmp_credentials"][0].name == "dc-snmp"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_start_discovery_passes_snmp_context_name_to_engine() -> None:
    engine = _FakeEngine()
    task_store = _FakeTaskStore()
    handler = DiscoveryRequestHandler(
        engine=cast(DiscoveryEngine, engine),
        task_store=cast(TaskStore, task_store),
    )

    await handler.start_discovery(
        DiscoveryRequest(
            targets=["10.0.0.0/24"],
            snmp_credentials=[
                SnmpCredentialModel(
                    name="tenant-snmp",
                    version="V3",
                    username="snmp-user",
                    context_name="tenant-a",
                )
            ],
        )
    )

    credential = engine.captured["snmp_credentials"][0]
    assert credential.name == "tenant-snmp"
    assert credential.version == "v3"
    assert credential.context_name == "tenant-a"


@pytest.mark.unit
def test_snmp_credential_model_rejects_invalid_version() -> None:
    with pytest.raises(ValueError, match="version must be one of v1, v2c, or v3"):
        SnmpCredentialModel(version="v2")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_task_status_does_not_include_mac_field() -> None:
    engine = _FakeEngine()
    task_store = _FakeTaskStore(
        task=DiscoveryTask(
            id="task-123",
            status=TaskStatus.COMPLETED,
            targets=["10.0.0.0/24"],
            total_hosts=1,
            completed_hosts=1,
            devices=[
                DiscoveredDevice(
                    ip="10.0.0.1",
                    vendor="Cisco",
                    model="N9K",
                    method="ssh",
                    protocol=["SSH"],
                    ssh_port=22,
                    ssh_credential_name="ops-ssh",
                )
            ],
        )
    )
    handler = DiscoveryRequestHandler(
        engine=cast(DiscoveryEngine, engine),
        task_store=cast(TaskStore, task_store),
    )

    response = await handler.get_task_status("task-123")

    payload = response.model_dump()
    assert payload["devices"][0]["ip"] == "10.0.0.1"
    assert payload["devices"][0]["vendor"] == "Cisco"
    assert payload["devices"][0]["ssh_credential_name"] == "ops-ssh"
    assert "serial_number" in payload["devices"][0]
    assert "mac" not in payload["devices"][0]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_task_hosts_returns_credential_name_and_logs() -> None:
    engine = _FakeEngine()
    task_store = _FakeTaskStore(
        task=DiscoveryTask(id="task-123"),
        hosts=[
            DiscoveryHostResult(
                id=1,
                task_id="task-123",
                ip="10.0.0.1",
                status="Success",
                result_key="success",
                protocol=["SSH"],
                ssh_port=22,
                ssh_credential_name="ops-ssh",
                vendor="Cisco",
                model="N9K",
                hostname="edge-sw-01",
                logs=[
                    DiscoveryHostLog(
                        id=11,
                        task_id="task-123",
                        ip="10.0.0.1",
                        host_result_id=1,
                        step_code="ssh_connect",
                        step="SSH connect",
                        status="Success",
                        message="SSH port 22 probe succeeded",
                    )
                ],
            )
        ],
    )
    handler = DiscoveryRequestHandler(
        engine=cast(DiscoveryEngine, engine),
        task_store=cast(TaskStore, task_store),
    )

    response = await handler.get_task_hosts("task-123", include_logs=True)

    payload = response.model_dump()
    assert payload["hosts"][0]["ssh_credential_name"] == "ops-ssh"
    assert payload["hosts"][0]["protocol"] == ["SSH"]
    assert payload["hosts"][0]["logs"][0]["step_code"] == "ssh_connect"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_collect_snmp_uses_request_timeout_and_returns_value() -> None:
    engine = _FakeEngine()
    task_store = _FakeTaskStore()
    fake_client = _FakeSnmpClient(timeout=0.0, retries=0)

    def client_factory(timeout: float, retries: int) -> _FakeSnmpClient:
        fake_client.timeout = timeout
        fake_client.retries = retries
        return fake_client

    handler = DiscoveryRequestHandler(
        engine=cast(DiscoveryEngine, engine),
        task_store=cast(TaskStore, task_store),
        snmp_retries=3,
        snmp_client_factory=cast(Callable[..., SnmpClient], client_factory),
    )

    response = await handler.collect_snmp(
        SnmpCollectRequest(
            ip="10.0.0.8",
            port=1161,
            oid="1.3.6.1.2.1.1.1.0",
            timeout_secs=7,
            version="v2c",
            community="public",
        )
    )

    assert response.success is True
    assert response.value == "sysDescr"
    assert fake_client.timeout == 7.0
    assert fake_client.retries == 3
    assert fake_client.captured["host"] == "10.0.0.8"
    assert fake_client.captured["port"] == 1161


@pytest.mark.unit
@pytest.mark.asyncio
async def test_collect_snmp_returns_failure_message() -> None:
    engine = _FakeEngine()
    task_store = _FakeTaskStore()
    fake_client = _FakeSnmpClient(timeout=0.0, retries=0)
    fake_client.response = SnmpResult(success=False, error="Invalid SNMP OID: invalid-oid")

    handler = DiscoveryRequestHandler(
        engine=cast(DiscoveryEngine, engine),
        task_store=cast(TaskStore, task_store),
        snmp_client_factory=cast(
            Callable[..., SnmpClient],
            lambda timeout, retries: fake_client,
        ),
    )

    response = await handler.collect_snmp(
        SnmpCollectRequest(
            ip="10.0.0.8",
            oid="1.3.6.1.2.1.1.1.0",
            timeout_secs=5,
            version="v2c",
            community="public",
        )
    )

    assert response.success is False
    assert response.value is None
    assert response.msg == "Invalid SNMP OID: invalid-oid"
