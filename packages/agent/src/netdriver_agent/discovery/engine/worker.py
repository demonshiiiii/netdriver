#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Discovery worker process entrypoint and runtime."""

from __future__ import annotations

import asyncio
import importlib
import json
import signal
import sys
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass
from typing import TypeVar

from netdriver_core.log import logman
from netdriver_core.nmap.models import ScanResult
from netdriver_core.nmap.scanner import NmapScanner
from netdriver_core.snmp.client import SNMP_OIDS, SnmpClient
from netdriver_core.snmp.models import SnmpCredential

from netdriver_agent.discovery.engine.models import (
    DiscoveredDevice,
    HostResultKey,
    HostStatus,
    TaskStatus,
)
from netdriver_agent.discovery.engine.task_store import TaskStore
from netdriver_agent.discovery.oid.vendor_oid_map import get_vendor_snmp_detail_oids
from netdriver_agent.discovery.parsing import (
    DiscoveryFieldMap,
    get_snmp_parse_rules,
    parse_discovery_template
)
from netdriver_agent.discovery.probe.base_ssh_probe import SshProbe
from netdriver_agent.discovery.probe.identifier import DeviceIdentifier
from netdriver_agent.discovery.probe.models import DeviceProfile, SnmpProbeResult, SshCredential

log = logman.logger
ProbeCredential = TypeVar("ProbeCredential", SnmpCredential, SshCredential)


@dataclass(slots=True)
class DiscoveryWorkerPayload:
    """Serializable worker payload for a discovery task."""

    task_id: str
    db_path: str
    nmap_path: str
    targets: list[str]
    ssh_ports: list[int]
    snmp_ports: list[int]
    ssh_credentials: list[dict[str, str]]
    snmp_credentials: list[dict[str, str | None]]
    max_concurrent_probes: int
    probe_timeout: float
    ssh_connect_timeout: float
    ssh_read_timeout: float
    snmp_timeout: float
    snmp_retries: int
    plugin_modules: list[str]
    parse_rule_result_mode: str = "overwrite"

    def to_json(self) -> str:
        """Serialize the worker payload to JSON."""
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, payload: str) -> "DiscoveryWorkerPayload":
        """Deserialize a worker payload from JSON."""
        return cls(**json.loads(payload))


class DiscoveryTaskWorker:
    """Runs the discovery pipeline inside a dedicated subprocess."""

    def __init__(
        self,
        task_store: TaskStore,
        nmap_path: str = "nmap",
        max_concurrent_probes: int = 50,
        probe_timeout: float = 30.0,
        ssh_connect_timeout: float = 10.0,
        ssh_read_timeout: float = 5.0,
        snmp_timeout: float = 5.0,
        snmp_retries: int = 1,
        parse_rule_result_mode: str = "overwrite",
        plugin_modules: list[str] | None = None,
    ) -> None:
        self._task_store = task_store
        self._nmap_scanner = NmapScanner(nmap_path=nmap_path)
        self._snmp_client = SnmpClient(
            timeout=snmp_timeout,
            retries=snmp_retries,
            engine_pool_size=max_concurrent_probes,
        )
        self._identifier: DeviceIdentifier | None = None
        self._max_concurrent = max_concurrent_probes
        self._probe_timeout = probe_timeout
        self._ssh_connect_timeout = ssh_connect_timeout
        self._ssh_read_timeout = ssh_read_timeout
        self._parse_rule_result_mode = self._normalize_parse_rule_result_mode(
            parse_rule_result_mode
        )
        self._plugin_modules = plugin_modules or []

        self._load_vendor_probes()

    def _load_vendor_probes(self) -> None:
        """Import plugin modules to trigger IPluginRegistry registration."""
        for module_path in self._plugin_modules:
            try:
                importlib.import_module(module_path)
            except ImportError as exc:
                log.warning(f"Failed to load plugin module {module_path}: {exc}")

    async def close(self) -> None:
        """Close long-lived probe resources."""
        await self._snmp_client.aclose()

    def _get_identifier(self) -> DeviceIdentifier:
        """Lazy-init DeviceIdentifier."""
        if self._identifier is None:
            self._identifier = DeviceIdentifier()
        return self._identifier

    async def _probe_with_credentials(
        self,
        host: str,
        port: int,
        credentials: list[ProbeCredential],
        identifier: DeviceIdentifier,
        probe_name: str,
        format_credential_label: Callable[[ProbeCredential], str],
        probe_func: Callable[
            ...,
            Awaitable[dict[str, str] | str | None],
        ],
        probe_kwargs: Mapping[str, object] | None = None,
        summary_logger: Callable[[str, str], Awaitable[None]] | None = None,
    ) -> tuple[dict[str, str] | None, str | None]:
        """Probe a host with credentials sequentially and continue after single timeouts.

        Returns:
            Tuple of (result_dict, failure_reason).
            failure_reason can be: 'auth_failed', 'timeout', or None on success.
        """
        resolved_probe_kwargs = dict(probe_kwargs or {})
        attempted = 0
        timed_out = False
        auth_failed = False

        for credential in credentials:
            attempted += 1
            probe_task = asyncio.create_task(
                probe_func(
                    host,
                    port,
                    [credential],
                    identifier,
                    **resolved_probe_kwargs,
                )
            )
            try:
                result = await asyncio.wait_for(
                    asyncio.shield(probe_task),
                    timeout=self._probe_timeout,
                )
            except asyncio.TimeoutError:
                timed_out = True
                probe_task.cancel()
                probe_task.add_done_callback(self._consume_cancelled_probe_task)
                log.debug(
                    f"{probe_name} probe timeout for {host}:{port} "
                    f"with {format_credential_label(credential)}"
                )
                continue
            except Exception:
                if not probe_task.done():
                    probe_task.cancel()
                    probe_task.add_done_callback(self._consume_cancelled_probe_task)
                raise

            if isinstance(result, str):
                if result == "timeout":
                    timed_out = True
                elif result == "auth_failed":
                    auth_failed = True
                else:
                    auth_failed = True
            elif result:
                if summary_logger is not None:
                    await summary_logger(
                        "Success",
                        f"{probe_name} authentication succeeded with "
                        f"{format_credential_label(credential)} on port {port}",
                    )
                return result, None
            else:
                auth_failed = True

        # Determine failure reason
        if attempted == 0:
            return None, None

        failure_reason = None
        if timed_out:
            failure_reason = "timeout"
            message = (
                f"All {probe_name} credentials timed out on port {port} "
                f"after {attempted} attempt(s)"
            )
        elif auth_failed:
            failure_reason = "auth_failed"
            message = (
                f"All {probe_name} credentials failed authentication on port {port} "
                f"after {attempted} attempt(s)"
            )
        else:
            message = (
                f"All {probe_name} credentials failed on port {port} "
                f"after {attempted} attempt(s)"
            )

        if summary_logger is not None:
            await summary_logger("Failed", message)

        return None, failure_reason

    @staticmethod
    def _consume_cancelled_probe_task(task: asyncio.Task) -> None:
        """Consume cancelled probe task results to avoid unhandled task warnings."""
        with suppress(asyncio.CancelledError, Exception):
            task.result()

    async def run(
        self,
        task_id: str,
        targets: list[str],
        ssh_ports: list[int],
        snmp_ports: list[int],
        ssh_credentials: list[SshCredential],
        snmp_credentials: list[SnmpCredential],
    ) -> None:
        """Execute the full discovery pipeline."""
        try:
            await self._task_store.set_status(task_id, TaskStatus.RUNNING)
            log.info(f"Discovery task {task_id}: starting scan for targets {targets}")

            scan_results = await self._nmap_scanner.scan(
                targets,
                ssh_ports=ssh_ports,
                snmp_ports=snmp_ports,
            )
            total = len(scan_results)
            await self._task_store.update_progress(task_id, 0, total)
            matched = sum(
                1 for scan_result in scan_results if scan_result.has_snmp or scan_result.has_ssh
            )
            skipped_scan_results = [
                scan_result
                for scan_result in scan_results
                if not scan_result.has_snmp and not scan_result.has_ssh
            ]
            matched_scan_results = [
                scan_result
                for scan_result in scan_results
                if scan_result.has_snmp or scan_result.has_ssh
            ]

            log.info(
                f"Discovery task {task_id}: scan found {total} host(s), "
                f"{matched} matched target ports"
            )

            if total == 0:
                await self._task_store.set_status(task_id, TaskStatus.COMPLETED)
                return

            semaphore = asyncio.Semaphore(self._max_concurrent)
            completed = 0

            if skipped_scan_results:
                await asyncio.gather(
                    *(
                        self._probe_and_store(
                            task_id=task_id,
                            scan_result=scan_result,
                            ssh_credentials=ssh_credentials,
                            snmp_credentials=snmp_credentials,
                        )
                        for scan_result in skipped_scan_results
                    ),
                    return_exceptions=False,
                )
                completed = len(skipped_scan_results)
                await self._task_store.update_progress(task_id, completed, total)

            async def probe_host(scan_result: ScanResult) -> None:
                nonlocal completed
                async with semaphore:
                    try:
                        await self._probe_and_store(
                            task_id=task_id,
                            scan_result=scan_result,
                            ssh_credentials=ssh_credentials,
                            snmp_credentials=snmp_credentials,
                        )
                    except asyncio.CancelledError:
                        raise
                    except (OSError, RuntimeError, ValueError) as exc:
                        log.warning(
                            f"Discovery task {task_id}: probe failed for {scan_result.ip}: {exc}"
                        )
                    finally:
                        completed += 1
                        await self._task_store.update_progress(task_id, completed, total)

            await asyncio.gather(
                *(probe_host(scan_result) for scan_result in matched_scan_results),
                return_exceptions=False,
            )

            await self._task_store.set_status(task_id, TaskStatus.COMPLETED)
            log.info(f"Discovery task {task_id}: completed")
        except asyncio.CancelledError:
            log.info(f"Discovery task {task_id}: cancelled")
            await self._task_store.set_status(task_id, TaskStatus.CANCELLED)
            raise
        except (
            OSError,
            RuntimeError,
            ValueError,
        ) as exc:
            log.error(f"Discovery task {task_id}: failed: {exc}")
            await self._task_store.set_status(task_id, TaskStatus.FAILED, str(exc))

    async def _probe_and_store(
        self,
        task_id: str,
        scan_result: ScanResult,
        ssh_credentials: list[SshCredential],
        snmp_credentials: list[SnmpCredential],
    ) -> None:
        """Probe a single host and store result."""
        host = scan_result.ip
        identifier = self._get_identifier()
        device = DiscoveredDevice(ip=host)
        host_result_id = await self._record_host_result(
            task_id,
            host,
            status=HostStatus.SCANNING,
            result_key=HostResultKey.SCANNING,
            hostname=scan_result.hostname,
        )
        await self._record_host_log(
            task_id,
            host,
            host_result_id,
            "start",
            "Scan started",
            "Running",
            f"Starting scan for {host}",
        )
        await self._record_host_log(
            task_id,
            host,
            host_result_id,
            "ping",
            "Port scan",
            "Success",
            f"Nmap detected open ports: {scan_result.open_ports}",
        )

        if not scan_result.has_snmp and not scan_result.has_ssh:
            port_closed_message = (
                "Nmap did not report any configured SNMP or SSH ports for this host; "
                "target ports may be closed or filtered"
            )
            await self._record_host_log(
                task_id,
                host,
                host_result_id,
                "port_closed",
                "Port closed",
                HostStatus.PORT_CLOSED,
                port_closed_message,
            )
            await self._record_host_result(
                task_id,
                host,
                status=HostStatus.PORT_CLOSED,
                result_key=HostResultKey.PORT_CLOSED,
                error_message=port_closed_message,
                completed=True,
            )
            return

        snmp_success = False
        snmp_probe_attempted = False
        snmp_failure_reason = None
        if scan_result.has_snmp and snmp_credentials:
            for snmp_port in scan_result.snmp_ports:
                snmp_probe_attempted = True
                await self._record_host_log(
                    task_id,
                    host,
                    host_result_id,
                    "snmp_connect",
                    "SNMP connect",
                    "Running",
                    f"Trying SNMP port {snmp_port}",
                )
                snmp_result, snmp_failure_reason = await self._probe_with_credentials(
                    host=host,
                    port=snmp_port,
                    credentials=snmp_credentials,
                    identifier=identifier,
                    probe_name="SNMP",
                    format_credential_label=self._format_snmp_credential_label,
                    probe_func=self._probe_snmp,
                    probe_kwargs={
                        "event_logger": self._make_host_event_logger(
                            task_id,
                            host,
                            host_result_id,
                        )
                    },
                    summary_logger=self._make_protocol_summary_logger(
                        task_id,
                        host,
                        host_result_id,
                        "snmp_auth",
                        "SNMP authentication",
                    ),
                )
                if snmp_result:
                    self._apply_snmp_result(device, snmp_result, snmp_port)
                    await self._record_host_log(
                        task_id,
                        host,
                        host_result_id,
                        "snmp_vendor_detect",
                        "SNMP vendor detection",
                        *self._build_identification_log(
                            device,
                            success_message_prefix="Detected device",
                            inconclusive_message="SNMP probe succeeded but device identification was inconclusive",
                        ),
                    )
                    snmp_success = True
                    snmp_failure_reason = None
                    break

        if scan_result.has_snmp and not snmp_credentials:
            await self._record_host_log(
                task_id,
                host,
                host_result_id,
                "snmp_connect",
                "SNMP connect",
                "Skipped",
                "No SNMP credentials configured",
            )

        ssh_success = False
        ssh_failure_reason = None
        if scan_result.has_ssh and ssh_credentials:
            for ssh_port in scan_result.ssh_ports:
                await self._record_host_log(
                    task_id,
                    host,
                    host_result_id,
                    "ssh_connect",
                    "SSH connect",
                    "Running",
                    f"Trying SSH port {ssh_port}",
                )
                ssh_result, ssh_failure_reason = await self._probe_with_credentials(
                    host=host,
                    port=ssh_port,
                    credentials=ssh_credentials,
                    identifier=identifier,
                    probe_name="SSH",
                    format_credential_label=self._format_ssh_credential_label,
                    probe_func=self._probe_ssh,
                    probe_kwargs={
                        "selection_profile": DeviceProfile.from_mapping(
                            {
                                "vendor": device.vendor,
                                "model": device.model,
                                "version": device.version,
                            }
                        )
                        if device.vendor
                        else DeviceProfile(),
                        "event_logger": self._make_host_event_logger(
                            task_id,
                            host,
                            host_result_id,
                        ),
                    },
                    summary_logger=self._make_protocol_summary_logger(
                        task_id,
                        host,
                        host_result_id,
                        "ssh_auth",
                        "SSH authentication",
                    ),
                )
                if ssh_result:
                    self._apply_ssh_result(
                        device,
                        ssh_result,
                        ssh_port,
                        snmp_success=snmp_success,
                    )
                    ssh_success = True
                    ssh_failure_reason = None
                    await self._record_host_log(
                        task_id,
                        host,
                        host_result_id,
                        "ssh_vendor_detect",
                        "SSH vendor detection",
                        *self._build_identification_log(
                            device,
                            success_message_prefix="Detected device",
                            inconclusive_message="SSH probe succeeded but device identification was inconclusive",
                        ),
                    )
                    break

        if scan_result.has_ssh and not ssh_credentials:
            await self._record_host_log(
                task_id,
                host,
                host_result_id,
                "ssh_connect",
                "SSH connect",
                "Skipped",
                "No SSH credentials configured",
            )

        if device.vendor or device.method:
            await self._task_store.add_device(task_id, device)
            protocol = self._resolve_result_protocol(
                device,
                snmp_success,
                ssh_success,
            )
            await self._record_host_result(
                task_id,
                host,
                status=HostStatus.SUCCESS,
                result_key=HostResultKey.SUCCESS,
                protocol=protocol,
                snmp_port=device.snmp_port,
                snmp_credential_name=device.snmp_credential_name,
                ssh_port=device.ssh_port,
                ssh_credential_name=device.ssh_credential_name,
                hostname=device.hostname,
                vendor=device.vendor,
                model=device.model,
                version=device.version,
                device_type=device.device_type,
                completed=True,
            )
            await self._record_host_log(
                task_id,
                host,
                host_result_id,
                "completed",
                "Scan completed",
                *self._build_completion_log(device),
            )
            log.info(
                f"Discovered: {host} -> "
                f"{self._format_device_summary(device) or 'unidentified device'} "
                f"via {device.method}"
            )
            return

        # Determine failure reason based on probe results
        final_status = HostStatus.FAILED
        final_result_key = HostResultKey.PROTOCOL_CONNECT_ERROR
        error_message = "SNMP/SSH probes did not identify a device"

        # Check if both protocols timed out
        if snmp_failure_reason == "timeout" or ssh_failure_reason == "timeout":
            final_status = HostStatus.TIMEOUT
            final_result_key = HostResultKey.TIMEOUT
            error_message = "Connection timeout during SNMP/SSH probes"
        # Check if both protocols failed authentication
        elif snmp_failure_reason == "auth_failed" or ssh_failure_reason == "auth_failed":
            final_status = HostStatus.AUTH_FAILED
            final_result_key = HostResultKey.AUTH_FAILED
            error_message = "All SNMP/SSH credentials failed authentication"
        # No probes were attempted
        elif not snmp_probe_attempted and not scan_result.has_ssh:
            final_status = HostStatus.FAILED
            final_result_key = HostResultKey.PROTOCOL_CONNECT_ERROR
            error_message = (
                "No SNMP or SSH probe was attempted because Nmap did not report any "
                "configured target ports for this host"
            )

        await self._record_host_result(
            task_id,
            host,
            status=final_status,
            result_key=final_result_key,
            error_message=error_message,
            completed=True,
        )
        await self._record_host_log(
            task_id,
            host,
            host_result_id,
            "completed",
            "Scan completed",
            final_status,
            error_message,
        )

    async def _record_host_result(
        self,
        task_id: str,
        ip: str,
        **kwargs: object,
    ) -> int | None:
        upsert_host_result = getattr(self._task_store, "upsert_host_result", None)
        if upsert_host_result is None:
            return None
        return await upsert_host_result(task_id, ip, **kwargs)

    async def _record_host_log(
        self,
        task_id: str,
        ip: str,
        host_result_id: int | None,
        step_code: str,
        step: str,
        status: str,
        message: str,
    ) -> None:
        add_host_log = getattr(self._task_store, "add_host_log", None)
        if add_host_log is None:
            return
        await add_host_log(task_id, ip, host_result_id, step_code, step, status, message)

    def _make_host_event_logger(
        self,
        task_id: str,
        ip: str,
        host_result_id: int | None,
    ) -> Callable[[str, str, str, str], Awaitable[None]]:
        async def log_event(step_code: str, step: str, status: str, message: str) -> None:
            await self._record_host_log(
                task_id,
                ip,
                host_result_id,
                step_code,
                step,
                status,
                message,
            )

        return log_event

    def _make_protocol_summary_logger(
        self,
        task_id: str,
        ip: str,
        host_result_id: int | None,
        step_code: str,
        step: str,
    ) -> Callable[[str, str], Awaitable[None]]:
        async def log_summary(status: str, message: str) -> None:
            await self._record_host_log(
                task_id,
                ip,
                host_result_id,
                step_code,
                step,
                status,
                message,
            )

        return log_summary

    @staticmethod
    def _resolve_result_protocol(
        device: DiscoveredDevice,
        snmp_success: bool,
        ssh_success: bool,
    ) -> list[str]:
        if snmp_success and ssh_success:
            return ["SNMP", "SSH"]
        if snmp_success:
            return ["SNMP"]
        if ssh_success:
            return ["SSH"]
        if device.protocol:
            return DiscoveryTaskWorker._normalize_protocol_values(device.protocol)
        method = device.method.strip().upper()
        return [method] if method in {"SNMP", "SSH"} else []

    @staticmethod
    def _normalize_protocol_values(protocol: list[str]) -> list[str]:
        return [
            value.strip().upper()
            for value in protocol
            if value.strip().upper() in {"SNMP", "SSH"}
        ]

    @staticmethod
    def _format_protocol_label(protocol: list[str]) -> str:
        values = DiscoveryTaskWorker._normalize_protocol_values(protocol)
        return "/".join(values) if values else "Probe"

    @staticmethod
    def _format_device_summary(device: DiscoveredDevice) -> str:
        """Format vendor/model/version into a concise device summary."""
        return " / ".join(
            part for part in (device.vendor, device.model, device.version) if part
        )

    @classmethod
    def _build_identification_log(
        cls,
        device: DiscoveredDevice,
        *,
        success_message_prefix: str,
        inconclusive_message: str,
    ) -> tuple[str, str]:
        """Build a host log tuple for detection outcomes."""
        summary = cls._format_device_summary(device)
        if summary:
            return "Success", f"{success_message_prefix}: {summary}"
        return "Skipped", inconclusive_message

    @classmethod
    def _build_completion_log(cls, device: DiscoveredDevice) -> tuple[str, str]:
        """Build a host log tuple for the final completion step."""
        summary = cls._format_device_summary(device)
        if summary:
            return "Success", f"Discovered device: {summary}"

        method_label = cls._format_protocol_label(device.protocol)
        return (
            "Success",
            f"{method_label} access succeeded but device identification was inconclusive",
        )

    @staticmethod
    def _format_snmp_credential_label(credential: SnmpCredential) -> str:
        """Format a human-readable SNMP credential label for logs."""
        if credential.name:
            return f"credential '{credential.name}'"
        label = credential.community if credential.version == "v2c" else credential.username
        return f"credential '{label or '<unknown>'}'"

    @staticmethod
    def _format_ssh_credential_label(credential: SshCredential) -> str:
        """Format a human-readable SSH credential label for logs."""
        if credential.name:
            return f"credential '{credential.name}'"
        return f"user '{credential.username}'"

    @staticmethod
    def _apply_snmp_result(
        device: DiscoveredDevice,
        snmp_result: dict[str, str],
        snmp_port: int,
    ) -> None:
        """Apply a successful SNMP probe result to a discovered device."""
        device.vendor = snmp_result.get("vendor", "")
        device.model = snmp_result.get("model", "")
        device.version = snmp_result.get("version", "")
        device.hostname = snmp_result.get("hostname", "")
        device.device_type = snmp_result.get("device_type", "")
        device.serial_number = snmp_result.get("serial_number", "")
        device.snmp_port = snmp_port
        device.snmp_credential_name = snmp_result.get("credential_name") or device.snmp_credential_name
        device.snmp_community = snmp_result.get("community", "")
        device.method = "snmp"
        device.protocol = ["SNMP"]
        device.raw_data = snmp_result.get("raw_data", "")

    @staticmethod
    def _apply_ssh_result(
        device: DiscoveredDevice,
        ssh_result: dict[str, str],
        ssh_port: int,
        *,
        snmp_success: bool,
    ) -> None:
        """Apply a successful SSH probe result to a discovered device."""
        ssh_vendor = ssh_result.get("vendor", "")
        ssh_model = ssh_result.get("model", "")
        ssh_version = ssh_result.get("version", "")
        ssh_hostname = ssh_result.get("hostname", "")
        ssh_device_type = ssh_result.get("device_type", "")
        ssh_serial = ssh_result.get("serial_number", "")

        if not snmp_success:
            device.vendor = ssh_vendor
            device.model = ssh_model
            device.version = ssh_version
            device.hostname = ssh_hostname or device.hostname
            device.device_type = ssh_device_type or device.device_type
            device.method = "ssh"
            device.protocol = ["SSH"]
        else:
            if "SNMP" not in device.protocol:
                device.protocol.append("SNMP")
            if "SSH" not in device.protocol:
                device.protocol.append("SSH")
            if not device.vendor and ssh_vendor:
                device.vendor = ssh_vendor
            elif ssh_vendor and DiscoveryTaskWorker._normalize_value(device.vendor) != DiscoveryTaskWorker._normalize_value(ssh_vendor):
                log.warning(
                    f"Discovery vendor mismatch for {device.ip}: SNMP={device.vendor!r}, SSH={ssh_vendor!r}"
                )

            if ssh_model:
                device.model = ssh_model
            if ssh_version:
                device.version = ssh_version
            if ssh_hostname:
                device.hostname = ssh_hostname
            if ssh_device_type:
                device.device_type = ssh_device_type

        device.ssh_port = ssh_port
        device.ssh_credential_name = ssh_result.get("credential_name") or device.ssh_credential_name
        device.ssh_username = ssh_result.get("username", "")
        if ssh_serial:
            device.serial_number = ssh_serial
        device.raw_data = DiscoveryTaskWorker._merge_raw_data(
            device.raw_data,
            ssh_result.get("raw_data", ""),
        )

    async def _probe_snmp(
        self,
        host: str,
        port: int,
        credentials: list[SnmpCredential],
        identifier: DeviceIdentifier,
        *,
        event_logger: Callable[[str, str, str, str], Awaitable[None]] | None = None,
    ) -> dict[str, str] | str | None:
        """Run SNMP probe and return parsed device info dict."""
        result = await self._probe_snmp_system_info(
            host,
            port,
            credentials,
            event_logger=event_logger,
        )

        if not result.success:
            return None

        vendor = identifier.identify_by_oid(result.sys_object_id)
        model = ""
        version = ""

        if vendor and result.credential is not None:
            detail_oids = get_vendor_snmp_detail_oids(vendor)
            detail_data = await self._fetch_snmp_detail_data(
                host,
                port,
                result.credential,
                detail_oids,
            )
            model = self._extract_oid_values(detail_data, detail_oids.get("model"))
            version = self._extract_oid_values(detail_data, detail_oids.get("version"))
            serial_number = self._extract_oid_values(detail_data, detail_oids.get("serial_number"))
        else:
            serial_number = ""

        device_data = {
            "vendor": vendor or "",
            "model": model,
            "version": version,
            "device_type": "",
            "serial_number": serial_number,
            "credential_name": result.credential.name if result.credential else "",
            "hostname": result.sys_name,
            "community": result.community,
            "raw_data": result.sys_descr,
        }
        if vendor and result.credential is not None:
            parsed_fields = await self._run_snmp_parse_rules(
                host=host,
                port=port,
                credential=result.credential,
                vendor_key=vendor,
            )
            self._apply_parsed_fields(device_data, parsed_fields)

        return device_data

    async def _probe_snmp_system_info(
        self,
        host: str,
        port: int,
        credentials: list[SnmpCredential],
        *,
        event_logger: Callable[[str, str, str, str], Awaitable[None]] | None = None,
    ) -> SnmpProbeResult:
        """Try SNMP credentials and fetch standard system OIDs."""
        oids = [
            SNMP_OIDS["sysDescr"],
            SNMP_OIDS["sysObjectID"],
            SNMP_OIDS["sysName"],
        ]

        for credential in credentials:
            label = (
                credential.name
                or credential.community
                or credential.username
                or "<unknown>"
            )
            log.debug(f"SNMP probe {host}: trying credential '{label}'")

            result = await self._snmp_client.get(host, credential, oids, port=port)
            if not result.success or not result.data:
                continue

            sys_descr = result.data.get(SNMP_OIDS["sysDescr"], "")
            sys_object_id = result.data.get(SNMP_OIDS["sysObjectID"], "")
            sys_name = result.data.get(SNMP_OIDS["sysName"], "")

            if event_logger is not None:
                await event_logger(
                    "snmp_identify",
                    "SNMP identification",
                    "Success",
                    f"Read sysObjectID={sys_object_id or '<empty>'} sysName={sys_name or '<empty>'}",
                )

            log.info(f"SNMP probe {host}: success with credential '{label}'")
            log.debug(f"SNMP probe {host}: sysObjectID={sys_object_id}, sysDescr={sys_descr}")

            return SnmpProbeResult(
                success=True,
                host=host,
                community=credential.community or "",
                credential=credential,
                sys_object_id=sys_object_id,
                sys_descr=sys_descr,
                sys_name=sys_name,
            )

        log.info(f"SNMP probe {host}: all credentials failed")
        return SnmpProbeResult(
            success=False,
            host=host,
            error="All SNMP credentials failed",
        )

    async def _fetch_snmp_detail_data(
        self,
        host: str,
        port: int,
        credential: SnmpCredential,
        detail_oids: dict[str, list[str]],
    ) -> dict[str, str]:
        """Fetch vendor model/version OIDs when configured."""
        oids: list[str] = []
        for oid_list in detail_oids.values():
            oids.extend(oid_list)
        if not oids:
            return {}

        result = await self._snmp_client.get(host, credential, oids, port=port)
        if not result.success or not result.data:
            return {}

        return result.data

    @staticmethod
    def _extract_oid_values(mib_data: dict[str, str], oids: list[str] | None) -> str:
        """Extract the first non-empty value from a list of OIDs."""
        if oids is None:
            return ""
        for oid in oids:
            value = mib_data.get(oid, "")
            if value:
                return value
        return ""

    async def _probe_ssh(
        self,
        host: str,
        port: int,
        credentials: list[SshCredential],
        identifier: DeviceIdentifier,
        *,
        selection_profile: DeviceProfile | None = None,
        event_logger: Callable[[str, str, str, str], Awaitable[None]] | None = None,
    ) -> dict[str, str] | None:
        """Run SSH probe and return parsed device info dict."""
        probe = SshProbe()
        result = await probe.probe(
            host,
            port,
            credentials,
            identifier,
            connect_timeout=self._ssh_connect_timeout,
            read_timeout=self._ssh_read_timeout,
            selection_profile=selection_profile,
            event_logger=event_logger,
        )

        if not result.success:
            return result.failure_reason or None

        device_data = {
            "vendor": result.device_info.vendor if result.device_info else "",
            "model": result.device_info.model if result.device_info else "",
            "version": result.device_info.version if result.device_info else "",
            "hostname": result.device_info.hostname if result.device_info else "",
            "device_type": "",
            "serial_number": result.device_info.serial_number if result.device_info else "",
            "credential_name": result.credential.name if result.credential else "",
            "username": result.credential.username if result.credential else "",
            "raw_data": result.raw_output,
        }

        return device_data

    async def _run_snmp_parse_rules(
        self,
        *,
        host: str,
        port: int,
        credential: SnmpCredential,
        vendor_key: str,
    ) -> DiscoveryFieldMap:
        """Execute configured SNMP parse rules for a vendor."""
        parsed_fields: DiscoveryFieldMap = {}
        rules = get_snmp_parse_rules(vendor_key)
        if rules:
            log.debug(
                f"Discovery SNMP parse rules start for {host}:{port} "
                f"vendor={vendor_key!r} rule_count={len(rules)}"
            )

        for rule in rules:
            log.debug(
                f"Discovery SNMP parse rule request for {host}:{port} "
                f"vendor={vendor_key!r} oid={rule.oid!r}"
            )
            result = await self._snmp_client.get(host, credential, [rule.oid], port=port)
            if not result.success or not result.data:
                log.debug(
                    f"Discovery SNMP parse rule response empty for {host}:{port} "
                    f"oid={rule.oid!r} success={result.success} data={result.data!r}"
                )
                continue

            raw_value = result.data.get(rule.oid) or next(iter(result.data.values()), "")
            if not raw_value:
                log.debug(
                    f"Discovery SNMP parse rule response missing raw value for {host}:{port} "
                    f"oid={rule.oid!r} data={result.data!r}"
                )
                continue

            log.debug(
                f"Discovery SNMP parse rule response for {host}:{port} "
                f"oid={rule.oid!r} raw_value={raw_value!r}"
            )

            try:
                parsed_result = parse_discovery_template(rule.template, raw_value)
                log.debug(
                    f"Discovery SNMP parse rule parsed fields for {host}:{port} "
                    f"oid={rule.oid!r} fields={parsed_result!r}"
                )
                self._merge_discovery_fields(
                    parsed_fields,
                    parsed_result,
                )
            except Exception as exc:
                log.warning(
                    "Discovery SNMP parse rule for OID %r failed for %s:%s: %s",
                    rule.oid,
                    host,
                    port,
                    exc,
                )

        if vendor_key and not parsed_fields.get("vendor"):
            parsed_fields["vendor"] = vendor_key
        if rules:
            log.debug(
                f"Discovery SNMP parse rules final fields for {host}:{port} "
                f"vendor={vendor_key!r} fields={parsed_fields!r}"
            )
        return parsed_fields

    @staticmethod
    def _merge_discovery_fields(
        target: DiscoveryFieldMap,
        updates: DiscoveryFieldMap,
    ) -> None:
        """Fill only missing discovery fields."""
        for key, value in updates.items():
            if value and not target.get(key):
                target[key] = value

    @staticmethod
    def _overwrite_discovery_fields(
        target: DiscoveryFieldMap,
        updates: DiscoveryFieldMap,
    ) -> None:
        """Prefer non-empty parsed fields over existing values."""
        for key, value in updates.items():
            if value:
                target[key] = value

    def _apply_parsed_fields(
        self,
        target: DiscoveryFieldMap,
        updates: DiscoveryFieldMap,
    ) -> None:
        """Apply parsed fields using the configured merge strategy."""
        if self._parse_rule_result_mode == "merge":
            self._merge_discovery_fields(target, updates)
            return
        self._overwrite_discovery_fields(target, updates)

    @staticmethod
    def _normalize_parse_rule_result_mode(mode: str | None) -> str:
        """Normalize parse-rule merge mode."""
        normalized = (mode or "overwrite").strip().lower()
        if normalized in {"merge", "overwrite"}:
            return normalized
        log.warning(
            "Invalid discovery parse rule result mode %r, falling back to 'overwrite'",
            mode,
        )
        return "overwrite"

    @staticmethod
    def _normalize_value(value: str | None) -> str:
        """Normalize a string for comparisons."""
        return value.strip().lower() if value else ""

    @staticmethod
    def _looks_precise_model(model: str) -> bool:
        """Heuristic for distinguishing exact hardware models from generic families."""
        return any(char.isdigit() for char in model) or "-" in model or " " in model

    @staticmethod
    def _merge_raw_data(existing_raw_data: str, ssh_raw_data: str) -> str:
        """Merge SNMP and SSH raw output into a single text field."""
        if not existing_raw_data:
            return ssh_raw_data
        if not ssh_raw_data or existing_raw_data == ssh_raw_data:
            return existing_raw_data
        return f"[SNMP]\n{existing_raw_data}\n\n[SSH]\n{ssh_raw_data}"


async def _run_worker(payload: DiscoveryWorkerPayload) -> None:
    """Run a worker payload in an isolated task store connection."""
    task_store = TaskStore(db_path=payload.db_path)
    await task_store.init_db()

    worker: DiscoveryTaskWorker | None = None
    try:
        worker = DiscoveryTaskWorker(
            task_store=task_store,
            nmap_path=payload.nmap_path,
            max_concurrent_probes=payload.max_concurrent_probes,
            probe_timeout=payload.probe_timeout,
            ssh_connect_timeout=payload.ssh_connect_timeout,
            ssh_read_timeout=payload.ssh_read_timeout,
            snmp_timeout=payload.snmp_timeout,
            snmp_retries=payload.snmp_retries,
            parse_rule_result_mode=payload.parse_rule_result_mode,
            plugin_modules=payload.plugin_modules,
        )
        await worker.run(
            task_id=payload.task_id,
            targets=payload.targets,
            ssh_ports=payload.ssh_ports,
            snmp_ports=payload.snmp_ports,
            ssh_credentials=[
                SshCredential(**credential) for credential in payload.ssh_credentials
            ],
            snmp_credentials=[
                SnmpCredential(**{k: v for k, v in credential.items() if v is not None})
                for credential in payload.snmp_credentials
            ],
        )
    finally:
        if worker is not None:
            await worker.close()
        await task_store.close()


def run_worker(payload: DiscoveryWorkerPayload) -> int:
    """Run the async worker with signal-aware cancellation."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    task = loop.create_task(_run_worker(payload))

    def _handle_signal(_: int, __) -> None:
        if not task.done():
            task.cancel()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handle_signal)
        except ValueError:
            continue

    try:
        loop.run_until_complete(task)
    except asyncio.CancelledError:
        return 0
    finally:
        pending_tasks = [
            pending_task
            for pending_task in asyncio.all_tasks(loop)
            if not pending_task.done()
        ]
        for pending_task in pending_tasks:
            pending_task.cancel()
        if pending_tasks:
            loop.run_until_complete(
                asyncio.gather(*pending_tasks, return_exceptions=True)
            )
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()

    return 0


def main() -> int:
    """CLI entrypoint for the discovery worker subprocess."""
    if len(sys.argv) != 2:
        log.error("Discovery worker expects exactly one JSON payload argument")
        return 1

    try:
        payload = DiscoveryWorkerPayload.from_json(sys.argv[1])
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        log.error(f"Failed to parse discovery worker payload: {exc}")
        return 1

    return run_worker(payload)


if __name__ == "__main__":
    raise SystemExit(main())
