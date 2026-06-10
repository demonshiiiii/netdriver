#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from netdriver_agent.discovery.engine.task_store import TaskStore


@pytest.mark.unit
@pytest.mark.asyncio
async def test_init_db_creates_device_table_without_mac_column(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "discovery.db"
    task_store = TaskStore(db_path=str(db_path))

    await task_store.init_db()
    await task_store.close()

    with sqlite3.connect(db_path) as connection:
        device_columns = [
            row[1]
            for row in connection.execute("PRAGMA table_info(discovered_devices)")
        ]
        host_result_columns = [
            row[1]
            for row in connection.execute("PRAGMA table_info(discovery_host_results)")
        ]

    assert "mac" not in device_columns
    assert "snmp_credential_name" in device_columns
    assert "ssh_credential_name" in device_columns
    assert "snmp_credential_name" in host_result_columns
    assert "ssh_credential_name" in host_result_columns
