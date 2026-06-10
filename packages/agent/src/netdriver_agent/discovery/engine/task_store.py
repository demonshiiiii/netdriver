#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLite-based persistent task store for discovery tasks."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from netdriver_core.log import logman
from netdriver_agent.discovery.engine.models import (
    DiscoveredDevice,
    DiscoveryHostLog,
    DiscoveryHostResult,
    DiscoveryTask,
    TaskStatus,
)

log = logman.logger

_CREATE_TASKS_TABLE = """
CREATE TABLE IF NOT EXISTS discovery_tasks (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'PENDING',
    targets TEXT NOT NULL,
    total_hosts INTEGER DEFAULT 0,
    completed_hosts INTEGER DEFAULT 0,
    error_message TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

_CREATE_DEVICES_TABLE = """
CREATE TABLE IF NOT EXISTS discovered_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES discovery_tasks(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    vendor TEXT DEFAULT '',
    model TEXT DEFAULT '',
    version TEXT DEFAULT '',
    hostname TEXT DEFAULT '',
    device_type TEXT DEFAULT '',
    method TEXT DEFAULT '',
    snmp_port INTEGER,
    snmp_credential_name TEXT,
    ssh_port INTEGER,
    ssh_credential_name TEXT,
    ssh_username TEXT,
    snmp_community TEXT,
    raw_data TEXT DEFAULT '',
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

_CREATE_DEVICES_INDEX = """
CREATE INDEX IF NOT EXISTS idx_devices_task_id ON discovered_devices(task_id)
"""

_CREATE_HOST_RESULTS_TABLE = """
CREATE TABLE IF NOT EXISTS discovery_host_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES discovery_tasks(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Scanning',
    result_key TEXT NOT NULL DEFAULT 'scanning',
    error_message TEXT DEFAULT '',
    protocol TEXT,
    snmp_port INTEGER,
    snmp_credential_name TEXT,
    ssh_port INTEGER,
    ssh_credential_name TEXT,
    hostname TEXT,
    vendor TEXT,
    model TEXT,
    version TEXT,
    device_type TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    duration_ms INTEGER,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(task_id, ip)
)
"""

_CREATE_HOST_RESULTS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_host_results_task_id ON discovery_host_results(task_id)
"""

_CREATE_HOST_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS discovery_host_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES discovery_tasks(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    host_result_id INTEGER REFERENCES discovery_host_results(id) ON DELETE SET NULL,
    step_code TEXT DEFAULT '',
    step TEXT DEFAULT '',
    status TEXT DEFAULT '',
    message TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

_CREATE_HOST_LOGS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_host_logs_task_ip ON discovery_host_logs(task_id, ip)
"""


class TaskStore:
    """SQLite-backed persistent store for discovery tasks and results."""

    def __init__(self, db_path: str = "data/discovery.db"):
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def init_db(self) -> None:
        """Initialize database and create tables if needed."""
        db_path = Path(self._db_path)
        if db_path.parent != Path():
            db_path.parent.mkdir(parents=True, exist_ok=True)

        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._db.execute(_CREATE_TASKS_TABLE)
        await self._db.execute(_CREATE_DEVICES_TABLE)
        await self._db.execute(_CREATE_DEVICES_INDEX)
        await self._db.execute(_CREATE_HOST_RESULTS_TABLE)
        await self._db.execute(_CREATE_HOST_RESULTS_INDEX)
        await self._db.execute(_CREATE_HOST_LOGS_TABLE)
        await self._db.execute(_CREATE_HOST_LOGS_INDEX)
        await self._db.commit()
        log.info(f"TaskStore initialized: {self._db_path}")

    async def close(self) -> None:
        """Close database connection."""
        if self._db:
            await self._db.close()
            self._db = None

    async def create_task(self, targets: list[str]) -> str:
        """Create a new discovery task.

        Args:
            targets: List of CIDR/IP range strings.

        Returns:
            Generated task_id (UUID).
        """
        task_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        targets_json = json.dumps(targets)

        await self._db.execute(
            "INSERT INTO discovery_tasks (id, status, targets, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (task_id, TaskStatus.PENDING, targets_json, now, now),
        )
        await self._db.commit()
        log.info(f"Created discovery task: {task_id}")
        return task_id

    async def get_task(
        self,
        task_id: str,
    ) -> DiscoveryTask | None:
        """Get task by ID with all discovered devices.

        Args:
            task_id: Task UUID.

        Returns:
            DiscoveryTask or None if not found.
        """
        async with self._db.execute(
            "SELECT * FROM discovery_tasks WHERE id = ?", (task_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None

        task = self._row_to_task(row)

        # Fetch discovered devices
        async with self._db.execute(
            "SELECT * FROM discovered_devices WHERE task_id = ? ORDER BY discovered_at",
            (task_id,),
        ) as cursor:
            async for device_row in cursor:
                task.devices.append(self._row_to_device(device_row))
        return task

    async def list_tasks(self) -> list[DiscoveryTask]:
        """List all tasks (without devices for efficiency).

        Returns:
            List of DiscoveryTask (devices list will be empty).
        """
        tasks = []
        async with self._db.execute(
            "SELECT * FROM discovery_tasks ORDER BY created_at DESC"
        ) as cursor:
            async for row in cursor:
                tasks.append(self._row_to_task(row))
        return tasks

    async def set_status(self, task_id: str, status: TaskStatus, error_message: str = "") -> None:
        """Update task status.

        Args:
            task_id: Task UUID.
            status: New status.
            error_message: Error message (for FAILED status).
        """
        now = datetime.now(timezone.utc).isoformat()
        await self._db.execute(
            "UPDATE discovery_tasks SET status = ?, error_message = ?, updated_at = ? WHERE id = ?",
            (status, error_message, now, task_id),
        )
        await self._db.commit()

    async def update_progress(self, task_id: str, completed: int, total: int) -> None:
        """Update task progress counters.

        Args:
            task_id: Task UUID.
            completed: Number of completed hosts.
            total: Total number of hosts.
        """
        now = datetime.now(timezone.utc).isoformat()
        await self._db.execute(
            "UPDATE discovery_tasks SET completed_hosts = ?, total_hosts = ?, updated_at = ? WHERE id = ?",
            (completed, total, now, task_id),
        )
        await self._db.commit()

    async def add_device(self, task_id: str, device: DiscoveredDevice) -> None:
        """Add a discovered device to the task results.

        Args:
            task_id: Task UUID.
            device: Discovered device data.
        """
        now = datetime.now(timezone.utc).isoformat()
        await self._db.execute(
            """INSERT INTO discovered_devices
            (task_id, ip, vendor, model, version, hostname, device_type, method,
             snmp_port, snmp_credential_name, ssh_port, ssh_credential_name,
             ssh_username, snmp_community, raw_data, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task_id,
                device.ip,
                device.vendor,
                device.model,
                device.version,
                device.hostname,
                device.device_type,
                device.method,
                device.snmp_port,
                device.snmp_credential_name,
                device.ssh_port,
                device.ssh_credential_name,
                device.ssh_username,
                device.snmp_community,
                device.raw_data,
                now,
            ),
        )
        await self._db.commit()

    async def upsert_host_result(
        self,
        task_id: str,
        ip: str,
        status: str = "Scanning",
        result_key: str = "scanning",
        error_message: str = "",
        protocol: list[str] | None = None,
        snmp_port: int | None = None,
        snmp_credential_name: str | None = None,
        ssh_port: int | None = None,
        ssh_credential_name: str | None = None,
        hostname: str | None = None,
        vendor: str | None = None,
        model: str | None = None,
        version: str | None = None,
        device_type: str | None = None,
        completed: bool = False,
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        async with self._db.execute(
            "SELECT id, started_at FROM discovery_host_results WHERE task_id = ? AND ip = ?",
            (task_id, ip),
        ) as cursor:
            existing = await cursor.fetchone()

        completed_at = now if completed else None
        duration_ms = None
        if completed and existing and existing["started_at"]:
            try:
                started_at = datetime.fromisoformat(existing["started_at"])
                duration_ms = int(
                    (datetime.fromisoformat(now) - started_at).total_seconds() * 1000
                )
            except ValueError:
                duration_ms = None

        if existing:
            protocol_value = self._protocol_to_storage(protocol)
            await self._db.execute(
                """UPDATE discovery_host_results
                SET status = ?, result_key = ?, error_message = ?, protocol = COALESCE(?, protocol),
                    snmp_port = COALESCE(?, snmp_port),
                    snmp_credential_name = COALESCE(?, snmp_credential_name),
                    ssh_port = COALESCE(?, ssh_port),
                    ssh_credential_name = COALESCE(?, ssh_credential_name),
                    hostname = COALESCE(?, hostname),
                    vendor = COALESCE(?, vendor), model = COALESCE(?, model),
                    version = COALESCE(?, version), device_type = COALESCE(?, device_type),
                    completed_at = COALESCE(?, completed_at),
                    duration_ms = COALESCE(?, duration_ms), updated_at = ?
                WHERE id = ?""",
                (
                    status,
                    result_key,
                    error_message,
                    protocol_value,
                    snmp_port,
                    snmp_credential_name,
                    ssh_port,
                    ssh_credential_name,
                    hostname,
                    vendor,
                    model,
                    version,
                    device_type,
                    completed_at,
                    duration_ms,
                    now,
                    existing["id"],
                ),
            )
            await self._db.commit()
            return int(existing["id"])

        protocol_value = self._protocol_to_storage(protocol)
        await self._db.execute(
            """INSERT INTO discovery_host_results
            (task_id, ip, status, result_key, error_message, protocol,
             snmp_port, snmp_credential_name, ssh_port, ssh_credential_name,
             hostname, vendor, model, version, device_type, started_at, completed_at,
             duration_ms, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task_id,
                ip,
                status,
                result_key,
                error_message,
                protocol_value,
                snmp_port,
                snmp_credential_name,
                ssh_port,
                ssh_credential_name,
                hostname,
                vendor,
                model,
                version,
                device_type,
                now,
                completed_at,
                duration_ms,
                now,
            ),
        )
        await self._db.commit()
        async with self._db.execute(
            "SELECT id FROM discovery_host_results WHERE task_id = ? AND ip = ?",
            (task_id, ip),
        ) as cursor:
            row = await cursor.fetchone()
            return int(row["id"])

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
        now = datetime.now(timezone.utc).isoformat()
        await self._db.execute(
            """INSERT INTO discovery_host_logs
            (task_id, ip, host_result_id, step_code, step, status, message, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (task_id, ip, host_result_id, step_code, step, status, message, now),
        )
        await self._db.commit()

    async def list_host_results(
        self,
        task_id: str,
        include_logs: bool = False,
    ) -> list[DiscoveryHostResult]:
        hosts: list[DiscoveryHostResult] = []
        async with self._db.execute(
            "SELECT * FROM discovery_host_results WHERE task_id = ? ORDER BY started_at, id",
            (task_id,),
        ) as cursor:
            async for row in cursor:
                hosts.append(self._row_to_host_result(row))

        if include_logs:
            logs_by_host_id: dict[int, list[DiscoveryHostLog]] = {}
            logs_by_ip: dict[str, list[DiscoveryHostLog]] = {}
            async with self._db.execute(
                "SELECT * FROM discovery_host_logs WHERE task_id = ? ORDER BY created_at, id",
                (task_id,),
            ) as cursor:
                async for row in cursor:
                    log_item = self._row_to_host_log(row)
                    logs_by_ip.setdefault(log_item.ip, []).append(log_item)
                    host_result_id = row["host_result_id"]
                    if host_result_id is None:
                        continue
                    logs_by_host_id.setdefault(int(host_result_id), []).append(log_item)
            for host in hosts:
                if host.id is not None:
                    host.logs = logs_by_host_id.get(host.id, logs_by_ip.get(host.ip, []))
                else:
                    host.logs = logs_by_ip.get(host.ip, [])

        return hosts

    async def list_host_logs(self, task_id: str, ip: str) -> list[DiscoveryHostLog]:
        logs: list[DiscoveryHostLog] = []
        async with self._db.execute(
            "SELECT * FROM discovery_host_logs WHERE task_id = ? AND ip = ? ORDER BY created_at, id",
            (task_id, ip),
        ) as cursor:
            async for row in cursor:
                logs.append(self._row_to_host_log(row))
        return logs

    async def count_running_tasks(self) -> int:
        """Count currently running tasks."""
        async with self._db.execute(
            "SELECT COUNT(*) FROM discovery_tasks WHERE status IN (?, ?)",
            (TaskStatus.PENDING, TaskStatus.RUNNING),
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def cleanup_expired(self, retention_seconds: int) -> int:
        """Delete completed/failed tasks older than retention period.

        Args:
            retention_seconds: Maximum age in seconds.

        Returns:
            Number of tasks deleted.
        """
        cutoff = datetime.now(timezone.utc).timestamp() - retention_seconds
        cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()

        async with self._db.execute(
            "SELECT COUNT(*) FROM discovery_tasks WHERE status IN (?, ?, ?) AND updated_at < ?",
            (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED, cutoff_iso),
        ) as cursor:
            row = await cursor.fetchone()
            count = row[0] if row else 0

        if count > 0:
            await self._db.execute(
                "DELETE FROM discovery_tasks WHERE status IN (?, ?, ?) AND updated_at < ?",
                (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED, cutoff_iso),
            )
            await self._db.commit()
            log.info(f"Cleaned up {count} expired discovery task(s)")

        return count

    @staticmethod
    def _row_to_task(row) -> DiscoveryTask:
        """Convert database row to DiscoveryTask."""
        targets = json.loads(row["targets"]) if row["targets"] else []
        return DiscoveryTask(
            id=row["id"],
            status=TaskStatus(row["status"]),
            targets=targets,
            total_hosts=row["total_hosts"] or 0,
            completed_hosts=row["completed_hosts"] or 0,
            error_message=row["error_message"] or "",
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _row_to_device(row) -> DiscoveredDevice:
        """Convert database row to DiscoveredDevice."""
        return DiscoveredDevice(
            ip=row["ip"],
            vendor=row["vendor"] or "",
            model=row["model"] or "",
            version=row["version"] or "",
            hostname=row["hostname"] or "",
            device_type=row["device_type"] or "",
            method=row["method"] or "",
            protocol=TaskStore._device_protocol(row),
            snmp_port=row["snmp_port"],
            snmp_credential_name=row["snmp_credential_name"],
            ssh_port=row["ssh_port"],
            ssh_credential_name=row["ssh_credential_name"],
            ssh_username=row["ssh_username"],
            snmp_community=row["snmp_community"],
            raw_data=row["raw_data"] or "",
            discovered_at=row["discovered_at"],
        )

    @staticmethod
    def _row_to_host_result(row) -> DiscoveryHostResult:
        return DiscoveryHostResult(
            id=row["id"],
            task_id=row["task_id"],
            ip=row["ip"],
            status=row["status"] or "Scanning",
            result_key=row["result_key"] or "scanning",
            error_message=row["error_message"] or "",
            protocol=TaskStore._protocol_from_storage(row["protocol"]),
            snmp_port=row["snmp_port"],
            snmp_credential_name=row["snmp_credential_name"],
            ssh_port=row["ssh_port"],
            ssh_credential_name=row["ssh_credential_name"],
            hostname=row["hostname"],
            vendor=row["vendor"],
            model=row["model"],
            version=row["version"],
            device_type=row["device_type"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            duration_ms=row["duration_ms"],
        )

    @staticmethod
    def _protocol_to_storage(protocol: list[str] | None) -> str | None:
        if protocol is None:
            return None
        values = [
            value.strip().upper()
            for value in protocol
            if value.strip().upper() in {"SNMP", "SSH"}
        ]
        return json.dumps(values)

    @staticmethod
    def _protocol_from_storage(protocol: str | None) -> list[str]:
        if not protocol:
            return []
        try:
            value = json.loads(protocol)
        except json.JSONDecodeError:
            text = protocol.strip().upper()
            return [text] if text in {"SNMP", "SSH"} else []
        if isinstance(value, list):
            return [
                item.strip().upper()
                for item in value
                if isinstance(item, str) and item.strip().upper() in {"SNMP", "SSH"}
            ]
        if isinstance(value, str):
            text = value.strip().upper()
            return [text] if text in {"SNMP", "SSH"} else []
        return []

    @staticmethod
    def _device_protocol(row) -> list[str]:
        values: list[str] = []
        if row["snmp_port"] is not None:
            values.append("SNMP")
        if row["ssh_port"] is not None:
            values.append("SSH")
        if values:
            return values
        method = (row["method"] or "").strip().upper()
        return [method] if method in {"SNMP", "SSH"} else []

    @staticmethod
    def _row_to_host_log(row) -> DiscoveryHostLog:
        return DiscoveryHostLog(
            id=row["id"],
            task_id=row["task_id"],
            ip=row["ip"],
            host_result_id=row["host_result_id"],
            step_code=row["step_code"] or "",
            step=row["step"] or "",
            status=row["status"] or "",
            message=row["message"] or "",
            created_at=row["created_at"],
        )
