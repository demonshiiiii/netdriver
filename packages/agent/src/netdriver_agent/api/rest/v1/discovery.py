#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Discovery API endpoints."""

from dependency_injector.wiring import inject, Provide
from fastapi import Depends, Query
from fastapi.routing import APIRouter

from netdriver_agent.containers import Container
from netdriver_agent.handlers.discovery_handler import DiscoveryRequestHandler
from netdriver_agent.models.common import CommonResponse
from netdriver_agent.models.discovery import (
    DiscoveryRequest,
    DiscoveryResponse,
    DiscoveryHostLogsResponse,
    DiscoveryHostResultsResponse,
    DiscoveryStatusResponse,
    DiscoveryTaskSummary,
    SnmpCollectRequest,
    SnmpCollectResponse,
)
from netdriver_agent.route import LoggingApiRoute


router = APIRouter(prefix="/discovery", route_class=LoggingApiRoute, tags=["discovery"])


@router.post("", summary="Start a discovery task")
@inject
async def start_discovery(
    request: DiscoveryRequest,
    handler: DiscoveryRequestHandler = Depends(Provide[Container.discovery_handler]),
) -> DiscoveryResponse:
    """Start a network device auto-discovery task."""
    return await handler.start_discovery(request)


@router.post("/snmp/collect", summary="Run a single SNMP GET")
@inject
async def collect_snmp(
    request: SnmpCollectRequest,
    handler: DiscoveryRequestHandler = Depends(Provide[Container.discovery_handler]),
) -> SnmpCollectResponse:
    """Run a single SNMP GET request against a target device."""
    return await handler.collect_snmp(request)


@router.get("", summary="List all discovery tasks")
@inject
async def list_tasks(
    handler: DiscoveryRequestHandler = Depends(Provide[Container.discovery_handler]),
) -> list[DiscoveryTaskSummary]:
    """List all discovery tasks."""
    return await handler.list_tasks()


@router.get("/{task_id}", summary="Get discovery task status")
@inject
async def get_task_status(
    task_id: str,
    handler: DiscoveryRequestHandler = Depends(Provide[Container.discovery_handler]),
) -> DiscoveryStatusResponse:
    """Get discovery task status and results."""
    return await handler.get_task_status(task_id)


@router.get("/{task_id}/hosts", summary="Get discovery task host results")
@inject
async def get_task_hosts(
    task_id: str,
    include_logs: bool = Query(default=False),
    handler: DiscoveryRequestHandler = Depends(Provide[Container.discovery_handler]),
) -> DiscoveryHostResultsResponse:
    return await handler.get_task_hosts(task_id, include_logs=include_logs)


@router.get("/{task_id}/hosts/{ip}/logs", summary="Get discovery host logs")
@inject
async def get_task_host_logs(
    task_id: str,
    ip: str,
    handler: DiscoveryRequestHandler = Depends(Provide[Container.discovery_handler]),
) -> DiscoveryHostLogsResponse:
    return await handler.get_task_host_logs(task_id, ip)


@router.delete("/{task_id}", summary="Cancel a discovery task")
@inject
async def cancel_task(
    task_id: str,
    handler: DiscoveryRequestHandler = Depends(Provide[Container.discovery_handler]),
) -> CommonResponse:
    """Cancel a running discovery task."""
    await handler.cancel_task(task_id)
    return CommonResponse.ok(msg=f"Task {task_id} cancelled")
