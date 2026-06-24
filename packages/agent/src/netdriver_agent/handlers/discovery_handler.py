#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Handler for discovery API requests."""

from collections.abc import Callable

from netdriver_core.exception.errors import (
    DiscoveryTaskLimitExceeded,
    DiscoveryTaskNotFound,
)
from netdriver_core.log import logman
from netdriver_core.snmp.client import SnmpClient
from netdriver_core.snmp.models import SnmpCredential
from netdriver_agent.discovery.engine.discovery_engine import DiscoveryEngine
from netdriver_agent.discovery.engine.models import DiscoveryTask
from netdriver_agent.discovery.engine.task_store import TaskStore
from netdriver_agent.discovery.probe.models import SshCredential

from netdriver_agent.models.discovery import (
    DiscoveredDeviceModel,
    DiscoveryHostLogsResponse,
    DiscoveryHostResultsResponse,
    DiscoveryHostLogModel,
    DiscoveryHostResultModel,
    DiscoveryRequest,
    DiscoveryResponse,
    SnmpCollectRequest,
    SnmpCollectResponse,
    DiscoveryStatusResponse,
    DiscoveryTaskSummary,
)
from netdriver_agent.security.secret_decryption import SecretDecryptor

log = logman.logger


class DiscoveryRequestHandler:
    """Handles discovery API logic."""

    def __init__(
        self,
        engine: DiscoveryEngine,
        task_store: TaskStore,
        max_tasks: int = 5,
        snmp_retries: int = 1,
        snmp_client_factory: Callable[..., SnmpClient] = SnmpClient,
        secret_decryptor: SecretDecryptor | None = None,
    ):
        self._engine = engine
        self._task_store = task_store
        self._max_tasks = max_tasks
        self._snmp_retries = snmp_retries
        self._snmp_client_factory = snmp_client_factory
        self._secret_decryptor = secret_decryptor or SecretDecryptor()

    async def start_discovery(self, request: DiscoveryRequest) -> DiscoveryResponse:
        """Start a new discovery task.

        Args:
            request: DiscoveryRequest with targets and credentials.

        Returns:
            DiscoveryResponse with task_id.

        Raises:
            DiscoveryTaskLimitExceeded: If max concurrent tasks exceeded.
        """
        running = await self._task_store.count_running_tasks()
        if running >= self._max_tasks:
            raise DiscoveryTaskLimitExceeded(
                f"Maximum {self._max_tasks} concurrent discovery tasks allowed, "
                f"currently {running} running."
            )

        # Convert API models to internal models
        ssh_creds = []
        for index, credential in enumerate(request.ssh_credentials):
            ssh_creds.append(
                SshCredential(
                    name=credential.name,
                    username=credential.username,
                    password=self._secret_decryptor.decrypt_required(
                        credential.password,
                        field_name=f"ssh_credentials[{index}].password",
                    ),
                    enable_password=self._secret_decryptor.decrypt(
                        credential.enable_password,
                        field_name=f"ssh_credentials[{index}].enable_password",
                    ) or "",
                )
            )
        snmp_creds = []
        for index, credential in enumerate(request.snmp_credentials):
            snmp_creds.append(
                SnmpCredential(
                    name=credential.name,
                    community=self._secret_decryptor.decrypt(
                        credential.community,
                        field_name=f"snmp_credentials[{index}].community",
                    ),
                    version=credential.version,
                    username=credential.username,
                    auth_protocol=credential.auth_protocol,
                    auth_password=self._secret_decryptor.decrypt(
                        credential.auth_password,
                        field_name=f"snmp_credentials[{index}].auth_password",
                    ),
                    priv_protocol=credential.priv_protocol,
                    priv_password=self._secret_decryptor.decrypt(
                        credential.priv_password,
                        field_name=f"snmp_credentials[{index}].priv_password",
                    ),
                    context_name=credential.context_name,
                )
            )

        task_id = await self._engine.start_discovery(
            targets=request.targets,
            ssh_ports=request.ports.ssh,
            snmp_ports=request.ports.snmp,
            ssh_credentials=ssh_creds,
            snmp_credentials=snmp_creds,
            max_concurrent_probes=request.max_concurrent_probes,
            probe_timeout=request.probe_timeout,
        )

        log.info(f"Started discovery task {task_id} for targets {request.targets}")
        return DiscoveryResponse(
            code="OK",
            msg="",
            correlation_id=None,
            task_id=task_id,
        )

    async def get_task_status(self, task_id: str) -> DiscoveryStatusResponse:
        """Get task status and results.

        Args:
            task_id: Task UUID.

        Returns:
            DiscoveryStatusResponse with task details and discovered devices.

        Raises:
            DiscoveryTaskNotFound: If task not found.
        """
        task = await self._task_store.get_task(task_id)
        if not task:
            raise DiscoveryTaskNotFound(f"Discovery task '{task_id}' not found.")

        return self._task_to_response(task)

    async def get_task_hosts(
        self,
        task_id: str,
        include_logs: bool = False,
    ) -> DiscoveryHostResultsResponse:
        task = await self._task_store.get_task(task_id)
        if not task:
            raise DiscoveryTaskNotFound(f"Discovery task '{task_id}' not found.")
        hosts = await self._task_store.list_host_results(task_id, include_logs=include_logs)
        return DiscoveryHostResultsResponse(
            code="OK",
            msg="",
            correlation_id=None,
            task_id=task_id,
            hosts=[self._host_to_response(host) for host in hosts],
        )

    async def get_task_host_logs(
        self,
        task_id: str,
        ip: str,
    ) -> DiscoveryHostLogsResponse:
        task = await self._task_store.get_task(task_id)
        if not task:
            raise DiscoveryTaskNotFound(f"Discovery task '{task_id}' not found.")
        logs = await self._task_store.list_host_logs(task_id, ip)
        return DiscoveryHostLogsResponse(
            code="OK",
            msg="",
            correlation_id=None,
            task_id=task_id,
            ip=ip,
            logs=[self._log_to_response(log_item) for log_item in logs],
        )

    async def list_tasks(self) -> list[DiscoveryTaskSummary]:
        """List all discovery tasks.

        Returns:
            List of task summaries.
        """
        tasks = await self._task_store.list_tasks()
        return [
            DiscoveryTaskSummary(
                task_id=t.id,
                status=t.status,
                targets=t.targets,
                progress=t.progress,
                total_hosts=t.total_hosts,
                completed_hosts=t.completed_hosts,
                created_at=str(t.created_at) if t.created_at else None,
                updated_at=str(t.updated_at) if t.updated_at else None,
            )
            for t in tasks
        ]

    async def cancel_task(self, task_id: str) -> None:
        """Cancel a running task.

        Args:
            task_id: Task UUID.

        Raises:
            DiscoveryTaskNotFound: If task not found or already completed.
        """
        cancelled = await self._engine.cancel_task(task_id)
        if not cancelled:
            task = await self._task_store.get_task(task_id)
            if not task:
                raise DiscoveryTaskNotFound(f"Discovery task '{task_id}' not found.")
            # Task exists but is already done
            log.info(f"Discovery task {task_id} already in status {task.status}")

    async def collect_snmp(self, request: SnmpCollectRequest) -> SnmpCollectResponse:
        """Run a single SNMP GET against the target device."""
        client = self._snmp_client_factory(
            timeout=float(request.timeout_secs),
            retries=self._snmp_retries,
        )
        credential = SnmpCredential(
            community=self._secret_decryptor.decrypt(
                request.community,
                field_name="community",
            ),
            version=request.version,
            username=request.username,
            auth_protocol=request.auth_protocol,
            auth_password=self._secret_decryptor.decrypt(
                request.auth_password,
                field_name="auth_password",
            ),
            priv_protocol=request.priv_protocol,
            priv_password=self._secret_decryptor.decrypt(
                request.priv_password,
                field_name="priv_password",
            ),
            context_name=request.context_name,
        )
        try:
            result = await client.get(
                host=request.ip,
                credential=credential,
                oids=[request.oid],
                port=request.port,
            )
        finally:
            close_client = getattr(client, "aclose", None)
            if close_client is not None:
                await close_client()

        if result.success:
            value = None
            if result.data:
                value = result.data.get(request.oid)
                if value is None:
                    value = next(iter(result.data.values()), None)
            return SnmpCollectResponse(
                code="OK",
                msg="SNMP collect succeeded",
                correlation_id=None,
                success=True,
                value=value,
            )

        return SnmpCollectResponse(
            code="OK",
            msg=result.error or "SNMP collect failed",
            correlation_id=None,
            success=False,
            value=None,
        )

    @staticmethod
    def _task_to_response(task: DiscoveryTask) -> DiscoveryStatusResponse:
        """Convert internal task to API response."""
        devices = [
            DiscoveredDeviceModel(
                ip=d.ip,
                vendor=d.vendor,
                model=d.model,
                version=d.version,
                hostname=d.hostname,
                device_type=d.device_type,
                serial_number=d.serial_number,
                method=d.method,
                protocol=d.protocol,
                snmp_port=d.snmp_port,
                snmp_credential_name=d.snmp_credential_name,
                ssh_port=d.ssh_port,
                ssh_credential_name=d.ssh_credential_name,
                ssh_username=d.ssh_username,
                snmp_community=d.snmp_community,
                discovered_at=str(d.discovered_at) if d.discovered_at else None,
            )
            for d in task.devices
        ]
        return DiscoveryStatusResponse(
            code="OK",
            msg="",
            correlation_id=None,
            task_id=task.id,
            status=task.status,
            progress=task.progress,
            total_hosts=task.total_hosts,
            completed_hosts=task.completed_hosts,
            devices=devices,
            error_message=task.error_message,
            created_at=str(task.created_at) if task.created_at else None,
            updated_at=str(task.updated_at) if task.updated_at else None,
        )

    @staticmethod
    def _host_to_response(host) -> DiscoveryHostResultModel:
        return DiscoveryHostResultModel(
            id=host.id,
            task_id=host.task_id,
            ip=host.ip,
            status=host.status,
            result_key=host.result_key,
            error_message=host.error_message,
            protocol=host.protocol,
            snmp_port=host.snmp_port,
            snmp_credential_name=host.snmp_credential_name,
            ssh_port=host.ssh_port,
            ssh_credential_name=host.ssh_credential_name,
            hostname=host.hostname,
            vendor=host.vendor,
            model=host.model,
            version=host.version,
            device_type=host.device_type,
            started_at=str(host.started_at) if host.started_at else None,
            completed_at=str(host.completed_at) if host.completed_at else None,
            duration_ms=host.duration_ms,
            logs=[
                DiscoveryRequestHandler._log_to_response(log_item)
                for log_item in host.logs
            ],
        )

    @staticmethod
    def _log_to_response(log_item) -> DiscoveryHostLogModel:
        return DiscoveryHostLogModel(
            id=log_item.id,
            task_id=log_item.task_id,
            ip=log_item.ip,
            host_result_id=log_item.host_result_id,
            step_code=log_item.step_code,
            step=log_item.step,
            status=log_item.status,
            message=log_item.message,
            created_at=str(log_item.created_at) if log_item.created_at else None,
        )
