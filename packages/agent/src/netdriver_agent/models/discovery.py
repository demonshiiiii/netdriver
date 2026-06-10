#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pydantic models for discovery API request/response."""

from datetime import datetime
from typing import Self

from pydantic import BaseModel, Field, field_validator, model_validator

from netdriver_agent.models.common import CommonResponse


class SshCredentialModel(BaseModel):
    """SSH credential in API request."""
    name: str = ""
    username: str
    password: str
    enable_password: str = ""


class SnmpCredentialModel(BaseModel):
    """SNMP credential in API request."""
    name: str = ""
    community: str | None = None
    version: str = "v2c"
    username: str | None = None
    auth_protocol: str | None = None
    auth_password: str | None = None
    priv_protocol: str | None = None
    priv_password: str | None = None
    context_name: str | None = None

    @field_validator("version")
    @classmethod
    def validate_version(cls, version: str) -> str:
        normalized = version.strip().lower()
        if normalized not in {"v1", "v2c", "v3"}:
            raise ValueError("version must be one of v1, v2c, or v3")
        return normalized


class SnmpCollectRequest(BaseModel):
    """Request body for POST /api/v1/discovery/snmp/collect."""

    ip: str = Field(description="Target IP address", examples=["192.168.1.1"])
    port: int = Field(default=161, ge=1, le=65535, description="SNMP port")
    oid: str = Field(
        description="OID to query",
        examples=["1.3.6.1.2.1.1.1.0"],
    )
    timeout_secs: int = Field(default=5, ge=1, description="Request timeout in seconds")
    version: str = Field(default="v2c", description="SNMP version", examples=["v2c"])
    community: str | None = None
    username: str | None = None
    auth_protocol: str | None = None
    auth_password: str | None = None
    priv_protocol: str | None = None
    priv_password: str | None = None
    context_name: str | None = None

    @field_validator("oid")
    @classmethod
    def validate_oid(cls, oid: str) -> str:
        """Ensure the OID uses dotted numeric form."""
        normalized = oid.strip()
        parts = normalized.split(".")
        if (
            not normalized
            or any(not part.isdigit() for part in parts)
            or any(part == "" for part in parts)
        ):
            raise ValueError("OID must be a dotted numeric string")
        return normalized

    @field_validator("version")
    @classmethod
    def validate_version(cls, version: str) -> str:
        """Restrict supported SNMP versions."""
        normalized = version.strip().lower()
        if normalized not in {"v1", "v2c", "v3"}:
            raise ValueError("version must be one of v1, v2c, or v3")
        return normalized


class SnmpCollectResponse(CommonResponse):
    """Response for POST /api/v1/discovery/snmp/collect."""

    success: bool
    value: str | None = None


class DiscoveryPortsModel(BaseModel):
    """Protocol-scoped ports for discovery scan."""

    ssh: list[int] = Field(
        default_factory=lambda: [22],
        description="TCP ports to scan for SSH",
        examples=[[22]],
    )
    snmp: list[int] = Field(
        default_factory=lambda: [161],
        description="UDP ports to scan for SNMP",
        examples=[[161]],
    )

    @field_validator("ssh", "snmp")
    @classmethod
    def validate_ports(cls, ports: list[int]) -> list[int]:
        """Ensure ports are valid and deduplicated."""
        normalized_ports: list[int] = []
        for port in ports:
            if not 1 <= port <= 65535:
                raise ValueError("port must be between 1 and 65535")
            if port not in normalized_ports:
                normalized_ports.append(port)
        return normalized_ports

    @model_validator(mode="after")
    def ensure_ports_configured(self) -> Self:
        """Require at least one protocol port to scan."""
        if not self.ssh and not self.snmp:
            raise ValueError("at least one SSH or SNMP port must be configured")
        return self


class DiscoveryRequest(BaseModel):
    """Request body for POST /api/v1/discovery."""
    targets: list[str] = Field(
        ...,
        description="CIDR or IP ranges to scan",
        examples=[["192.168.1.0/24", "10.0.0.1-10"]],
    )
    ports: DiscoveryPortsModel = Field(
        default_factory=DiscoveryPortsModel,
        description="Protocol-scoped ports to scan",
        examples=[{"ssh": [22], "snmp": [161]}],
    )
    ssh_credentials: list[SshCredentialModel] = Field(
        default_factory=list,
        description="SSH credentials to try",
    )
    snmp_credentials: list[SnmpCredentialModel] = Field(
        default_factory=list,
        description="SNMP credentials to try",
    )
    max_concurrent_probes: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum concurrent probes",
    )
    probe_timeout: float = Field(
        default=30.0,
        gt=0,
        description="Per-probe timeout in seconds",
    )


class DiscoveredDeviceModel(BaseModel):
    """A discovered device in API response."""
    ip: str
    vendor: str = ""
    model: str = ""
    version: str = ""
    hostname: str = ""
    device_type: str = ""
    serial_number: str = ""
    method: str = ""
    protocol: list[str] = Field(default_factory=list)
    snmp_port: int | None = None
    snmp_credential_name: str | None = None
    ssh_port: int | None = None
    ssh_credential_name: str | None = None
    ssh_username: str | None = None
    snmp_community: str | None = None
    discovered_at: str | None = None


class DiscoveryHostLogModel(BaseModel):
    id: int | None = None
    task_id: str = ""
    ip: str = ""
    host_result_id: int | None = None
    step_code: str = ""
    step: str = ""
    status: str = ""
    message: str = ""
    created_at: str | None = None


class DiscoveryHostResultModel(BaseModel):
    id: int | None = None
    task_id: str = ""
    ip: str
    status: str = "Scanning"
    result_key: str = "scanning"
    error_message: str = ""
    protocol: list[str] = Field(default_factory=list)
    snmp_port: int | None = None
    snmp_credential_name: str | None = None
    ssh_port: int | None = None
    ssh_credential_name: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    model: str | None = None
    version: str | None = None
    device_type: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    duration_ms: int | None = None
    logs: list[DiscoveryHostLogModel] = Field(default_factory=list)


class DiscoveryResponse(CommonResponse):
    """Response for POST /api/v1/discovery (task created)."""
    task_id: str = Field(description="Discovery task ID for polling")


class DiscoveryStatusResponse(CommonResponse):
    """Response for GET /api/v1/discovery/{task_id}."""
    task_id: str
    status: str
    progress: float = Field(description="0.0 ~ 1.0")
    total_hosts: int = 0
    completed_hosts: int = 0
    devices: list[DiscoveredDeviceModel] = Field(default_factory=list)
    error_message: str = ""
    created_at: str | None = None
    updated_at: str | None = None


class DiscoveryHostResultsResponse(CommonResponse):
    task_id: str
    hosts: list[DiscoveryHostResultModel] = Field(default_factory=list)


class DiscoveryHostLogsResponse(CommonResponse):
    task_id: str
    ip: str
    logs: list[DiscoveryHostLogModel] = Field(default_factory=list)


class DiscoveryTaskSummary(BaseModel):
    """Summary of a discovery task for list endpoint."""
    task_id: str
    status: str
    targets: list[str] = Field(default_factory=list)
    progress: float = 0.0
    total_hosts: int = 0
    completed_hosts: int = 0
    created_at: str | None = None
    updated_at: str | None = None
