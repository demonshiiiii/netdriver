#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio

import pytest

from netdriver_core.snmp.client import SnmpClient
from netdriver_core.snmp.models import SnmpCredential


class _FakeEngine:
    def __init__(self) -> None:
        self.closed = False

    def closeDispatcher(self) -> None:
        self.closed = True


def _patch_snmp_value_objects(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "netdriver_core.snmp.client.UdpTransportTarget",
        lambda *args, **kwargs: object(),
    )
    monkeypatch.setattr(
        "netdriver_core.snmp.client.ContextData",
        lambda *args, **kwargs: object(),
    )
    monkeypatch.setattr("netdriver_core.snmp.client.ObjectIdentity", lambda oid: oid)
    monkeypatch.setattr("netdriver_core.snmp.client.ObjectType", lambda oid: oid)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_reuses_engine_until_client_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_engines: list[_FakeEngine] = []
    used_engines: list[_FakeEngine] = []

    monkeypatch.setattr(
        "netdriver_core.snmp.client.SnmpEngine",
        lambda: created_engines.append(_FakeEngine()) or created_engines[-1],
    )
    _patch_snmp_value_objects(monkeypatch)

    async def fake_get_cmd(engine, auth_data, transport, context, *object_types):
        used_engines.append(engine)
        return None, 0, 0, [("1.3.6.1.2.1.1.5.0", "edge-sw-01")]

    monkeypatch.setattr("netdriver_core.snmp.client.getCmd", fake_get_cmd)

    client = SnmpClient()
    first_result = await client.get(
        "10.0.0.10",
        SnmpCredential(name="public-snmp", community="public"),
        ["1.3.6.1.2.1.1.5.0"],
    )
    second_result = await client.get(
        "10.0.0.11",
        SnmpCredential(name="public-snmp", community="public"),
        ["1.3.6.1.2.1.1.5.0"],
    )

    assert first_result.success is True
    assert second_result.success is True
    assert len(created_engines) == 1
    assert used_engines == [created_engines[0], created_engines[0]]
    assert created_engines[0].closed is False

    client.close()

    assert created_engines[0].closed is True


@pytest.mark.unit
@pytest.mark.asyncio
async def test_engine_pool_creates_up_to_configured_concurrency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_engines: list[_FakeEngine] = []
    started = asyncio.Event()
    release = asyncio.Event()
    active_calls = 0

    monkeypatch.setattr(
        "netdriver_core.snmp.client.SnmpEngine",
        lambda: created_engines.append(_FakeEngine()) or created_engines[-1],
    )
    _patch_snmp_value_objects(monkeypatch)

    async def fake_get_cmd(engine, auth_data, transport, context, *object_types):
        nonlocal active_calls
        active_calls += 1
        if active_calls == 2:
            started.set()
        await release.wait()
        active_calls -= 1
        return None, 0, 0, [("1.3.6.1.2.1.1.5.0", "edge-sw-01")]

    monkeypatch.setattr("netdriver_core.snmp.client.getCmd", fake_get_cmd)

    client = SnmpClient(engine_pool_size=2)
    first = asyncio.create_task(
        client.get(
            "10.0.0.10",
            SnmpCredential(name="public-snmp", community="public"),
            ["1.3.6.1.2.1.1.5.0"],
        )
    )
    second = asyncio.create_task(
        client.get(
            "10.0.0.11",
            SnmpCredential(name="public-snmp", community="public"),
            ["1.3.6.1.2.1.1.5.0"],
        )
    )

    await asyncio.wait_for(started.wait(), timeout=1)

    assert len(created_engines) == 2

    release.set()
    await asyncio.gather(first, second)
    client.close()

    assert all(engine.closed for engine in created_engines)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_walk_returns_engine_to_pool_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_engines: list[_FakeEngine] = []
    calls = 0

    monkeypatch.setattr(
        "netdriver_core.snmp.client.SnmpEngine",
        lambda: created_engines.append(_FakeEngine()) or created_engines[-1],
    )
    _patch_snmp_value_objects(monkeypatch)

    async def fake_bulk_cmd(
        engine,
        auth_data,
        transport,
        context,
        non_repeaters,
        max_repetitions,
        object_type,
    ):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("snmp boom")
        return None, 0, 0, [
            ("1.3.6.1.2.1.1.5.0", "edge-sw-01"),
            ("1.3.6.1.2.1.1.6.0", "lab-a"),
        ]

    monkeypatch.setattr("netdriver_core.snmp.client.bulkCmd", fake_bulk_cmd)

    client = SnmpClient(engine_pool_size=1)
    failed_result = await client.walk(
        "10.0.0.10",
        SnmpCredential(name="public-snmp", community="public"),
        "1.3.6.1.2.1.1",
    )
    success_result = await client.walk(
        "10.0.0.11",
        SnmpCredential(name="public-snmp", community="public"),
        "1.3.6.1.2.1.1",
    )

    assert failed_result.success is False
    assert failed_result.error == "snmp boom"
    assert success_result.success is True
    assert len(created_engines) == 1
    assert created_engines[0].closed is False

    client.close()

    assert created_engines[0].closed is True
