#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class TaskStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class HostStatus(StrEnum):
    """Host-level discovery status."""
    SCANNING = "Scanning"
    SUCCESS = "Success"
    FAILED = "Failed"
    PORT_CLOSED = "PortClosed"
    AUTH_FAILED = "AuthFailed"
    TIMEOUT = "Timeout"
    PARSE_FAILED = "ParseFailed"


class HostResultKey(StrEnum):
    """Host result key for categorizing failure reasons."""
    SCANNING = "scanning"
    SUCCESS = "success"
    PORT_CLOSED = "port_closed"
    AUTH_FAILED = "auth_failed"
    TIMEOUT = "timeout"
    PARSE_FAILED = "parse_failed"
    PROTOCOL_CONNECT_ERROR = "protocol_connect_error"


@dataclass
class DiscoveredDevice:
    """A device discovered during a discovery task."""
    ip: str
    vendor: str = ""
    model: str = ""
    version: str = ""
    hostname: str = ""
    device_type: str = ""
    method: str = ""
    protocol: list[str] = field(default_factory=list)
    serial_number: str = ""
    snmp_port: int | None = None
    snmp_credential_name: str | None = None
    ssh_port: int | None = None
    ssh_credential_name: str | None = None
    ssh_username: str | None = None
    snmp_community: str | None = None
    raw_data: str = ""
    discovered_at: datetime | None = None


@dataclass
class DiscoveryHostLog:
    id: int | None = None
    task_id: str = ""
    ip: str = ""
    host_result_id: int | None = None
    step_code: str = ""
    step: str = ""
    status: str = ""
    message: str = ""
    created_at: datetime | str | None = None


@dataclass
class DiscoveryHostResult:
    id: int | None = None
    task_id: str = ""
    ip: str = ""
    status: str = "Scanning"
    result_key: str = "scanning"
    error_message: str = ""
    protocol: list[str] = field(default_factory=list)
    snmp_port: int | None = None
    snmp_credential_name: str | None = None
    ssh_port: int | None = None
    ssh_credential_name: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    model: str | None = None
    version: str | None = None
    device_type: str | None = None
    started_at: datetime | str | None = None
    completed_at: datetime | str | None = None
    duration_ms: int | None = None
    logs: list[DiscoveryHostLog] = field(default_factory=list)


@dataclass
class DiscoveryTask:
    """State of a discovery task."""
    id: str
    status: TaskStatus = TaskStatus.PENDING
    targets: list[str] = field(default_factory=list)
    total_hosts: int = 0
    completed_hosts: int = 0
    devices: list[DiscoveredDevice] = field(default_factory=list)
    error_message: str = ""
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @property
    def progress(self) -> float:
        if self.total_hosts == 0:
            return 0.0
        return self.completed_hosts / self.total_hosts
