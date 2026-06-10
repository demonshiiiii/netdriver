#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH probe for device identification using the plugin system."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

import asyncssh
import re

from netdriver_agent.client.channel import ReadBuffer
from netdriver_core.log import logman
from netdriver_core.plugin.core import PluginCore
from netdriver_core.ssh.algorithms import DEFAULT_ENCRYPTION_ALGS, DEFAULT_KEX_ALGS

from netdriver_agent.discovery.probe.models import DeviceInfo, DeviceProfile, SshCredential, SshProbeResult

if TYPE_CHECKING:
    from netdriver_agent.discovery.probe.identifier import DeviceIdentifier

log = logman.logger
ProbeEventLogger = Callable[[str, str, str, str], Awaitable[None] | None]


class SshProbe:
    """SSH probe that uses the plugin system for device identification."""

    _PROCESS_OPEN_TIMEOUT = 5.0
    _CONNECTION_CLOSE_TIMEOUT = 2.0
    _READ_IDLE_TIMEOUT = 2.0
    _OUTPUT_PREVIEW_LIMIT = 500
    _PROBE_PARSE_TIMEOUT = 3.0
    _MAX_AMBIGUOUS_PROMPT_CANDIDATES = 1
    _CONNECT_RETRIES = 1
    _CONNECT_RETRY_DELAY = 0.5
    _GENERIC_PROMPT_PATTERN = re.compile(
        r"\r?\n?[a-zA-Z0-9._\-\(\)/<>\[\]]+[>#\]\$]\s?$"
    )

    _SSH_CONFIG = {
        "known_hosts": None,
        "kex_algs": DEFAULT_KEX_ALGS,
        "encryption_algs": DEFAULT_ENCRYPTION_ALGS,
    }

    async def probe(
        self,
        host: str,
        port: int,
        credentials: list[SshCredential],
        identifier: DeviceIdentifier,
        connect_timeout: float = 10.0,
        read_timeout: float = 5.0,
        selection_profile: DeviceProfile | None = None,
        event_logger: ProbeEventLogger | None = None,
    ) -> SshProbeResult:
        """Full SSH probe using plugin-based identification."""

        resolved_profile = (selection_profile or DeviceProfile()).normalized()
        timed_out = False
        auth_failed = False

        for credential in credentials:
            log.debug(
                f"SSH probe {host}:{port}: trying user '{credential.username}' "
                f"with profile {resolved_profile.vendor}/{resolved_profile.model}/{resolved_profile.version}"
            )

            conn = None
            for attempt in range(self._CONNECT_RETRIES + 1):
                try:
                    conn = await asyncio.wait_for(
                        asyncssh.connect(
                            host,
                            port=port,
                            username=credential.username,
                            password=credential.password,
                            **self._SSH_CONFIG,
                        ),
                        timeout=connect_timeout,
                    )
                    break
                except asyncio.TimeoutError:
                    timed_out = True
                    log.debug(
                        f"SSH probe {host}:{port}: connect timeout for user "
                        f"'{credential.username}' on attempt {attempt + 1}"
                    )
                    if attempt < self._CONNECT_RETRIES:
                        await asyncio.sleep(self._CONNECT_RETRY_DELAY)
                        continue
                    break
                except asyncssh.PermissionDenied as exc:
                    auth_failed = True
                    log.debug(
                        f"SSH probe {host}:{port}: auth failed for user "
                        f"'{credential.username}': {exc}"
                    )
                    break
                except (asyncssh.DisconnectError, OSError) as exc:
                    log.debug(
                        f"SSH probe {host}:{port}: connect failed for user "
                        f"'{credential.username}': {exc}"
                    )
                    break
                except Exception as exc:
                    log.debug(
                        f"SSH probe {host}:{port}: unexpected error for user "
                        f"'{credential.username}': {exc}"
                    )
                    break
            if conn is None:
                continue

            log.info(f"SSH probe {host}:{port}: connected as '{credential.username}'")

            try:
                return await self._identify_device(
                    conn,
                    host,
                    port,
                    credential,
                    identifier,
                    read_timeout,
                    selection_profile=resolved_profile,
                )
            except Exception as exc:
                credential_label = self._format_credential_label(credential)
                await self._emit_event(
                    event_logger,
                    "ssh_identify",
                    "SSH identification",
                    "Failed",
                    f"SSH identification failed after login with {credential_label}: {exc}",
                )
                log.warning(f"SSH probe {host}:{port}: identification failed: {exc}")
                return SshProbeResult(
                    success=True,
                    host=host,
                    port=port,
                    credential=credential,
                    error=f"Connected but identification failed: {exc}",
                )
            finally:
                await self._close_connection(conn, host, port)

        if timed_out:
            failure_reason = "timeout"
            error = "All SSH credentials timed out"
        elif auth_failed:
            failure_reason = "auth_failed"
            error = "All SSH credentials failed authentication"
        else:
            failure_reason = ""
            error = "All SSH credentials failed"

        log.info(f"SSH probe {host}:{port}: {error}")
        return SshProbeResult(
            success=False,
            host=host,
            port=port,
            error=error,
            failure_reason=failure_reason,
        )

    async def execute_commands(
        self,
        host: str,
        port: int,
        credential: SshCredential,
        commands: list[str],
        connect_timeout: float = 10.0,
        read_timeout: float = 5.0,
    ) -> list[str]:
        """Execute commands over SSH and return outputs in input order."""
        if not commands:
            return []

        conn = await asyncio.wait_for(
            asyncssh.connect(
                host,
                port=port,
                username=credential.username,
                password=credential.password,
                **self._SSH_CONFIG,
            ),
            timeout=connect_timeout,
        )

        try:
            process = await asyncio.wait_for(
                conn.create_process(
                    term_type="ansi",
                    term_size=(1000, 100),
                ),
                timeout=self._PROCESS_OPEN_TIMEOUT,
            )

            try:
                await asyncio.wait_for(self._read_prompt(process), timeout=read_timeout)
            except asyncio.TimeoutError:
                log.debug(
                    f"SSH probe {host}:{port}: prompt read timeout before discovery rules"
                )

            outputs: list[str] = []
            for command in commands:
                process.stdin.write(command + "\n")
                try:
                    output = await asyncio.wait_for(
                        self._read_until_prompt(
                            process,
                            command,
                            self._GENERIC_PROMPT_PATTERN,
                        ),
                        timeout=read_timeout,
                    )
                except asyncio.TimeoutError:
                    log.debug(
                        f"SSH probe {host}:{port}: discovery command timeout for {command!r}"
                    )
                    output = ""
                outputs.append(output)

            return outputs
        finally:
            await self._close_connection(conn, host, port)

    async def _identify_device(
        self,
        conn: asyncssh.SSHClientConnection,
        host: str,
        port: int,
        credential: SshCredential,
        identifier: "DeviceIdentifier",
        read_timeout: float,
        *,
        selection_profile: DeviceProfile,
    ) -> SshProbeResult:
        """Identify device type via prompt matching and plugin probe commands."""

        process = await asyncio.wait_for(
            conn.create_process(
                term_type="ansi",
                term_size=(1000, 100),
            ),
            timeout=self._PROCESS_OPEN_TIMEOUT,
        )

        known_plugin_cls: type | None = None
        if selection_profile.vendor:
            known_plugin_cls = identifier.get_probe_plugin(
                selection_profile.vendor,
                selection_profile.model,
                selection_profile.version,
            )

        # Step 1: Read prompt
        prompt = ""
        welcome_output = ""
        prompt_pattern = (
            self._get_probe_prompt_pattern(known_plugin_cls)
            if known_plugin_cls
            else self._GENERIC_PROMPT_PATTERN
        )
        try:
            prompt, welcome_output = await asyncio.wait_for(
                self._read_prompt(process, prompt_pattern),
                timeout=read_timeout,
            )
        except asyncio.TimeoutError:
            log.debug(f"SSH probe {host}:{port}: prompt read timeout, using partial output")

        # Step 2: Determine candidate plugins
        candidates: list[type] = []
        if selection_profile.vendor:
            if known_plugin_cls:
                candidates.append(known_plugin_cls)
        else:
            matching_vendors = identifier.identify_by_prompt(prompt)
            if len(matching_vendors) > self._MAX_AMBIGUOUS_PROMPT_CANDIDATES:
                log.debug(
                    f"SSH probe {host}:{port}: prompt matched {len(matching_vendors)} vendors, "
                    "skipping vendor probe commands to avoid ambiguous command execution"
                )
                return SshProbeResult(
                    success=True,
                    host=host,
                    port=port,
                    credential=credential,
                    device_info=None,
                    raw_output=welcome_output,
                )
            for vendor in matching_vendors:
                plugin_cls = identifier.get_probe_plugin(vendor)
                if plugin_cls:
                    candidates.append(plugin_cls)
            if not candidates:
                candidates.append(PluginCore)

        # Step 3: Try each candidate plugin
        for plugin_cls in candidates:
            probe_cmd = plugin_cls.get_probe_command()
            probe_output = ""
            union_pattern = self._get_probe_prompt_pattern(plugin_cls)
            try:
                log.debug(
                    f"SSH probe {host}:{port}: running probe command {probe_cmd!r} "
                    f"with {plugin_cls.__name__}"
                )
                process.stdin.write(probe_cmd + "\n")
                probe_output = await asyncio.wait_for(
                    self._read_until_prompt(process, probe_cmd, union_pattern),
                    timeout=read_timeout,
                )
                log.debug(
                    f"SSH probe {host}:{port}: probe command {probe_cmd!r} "
                    f"returned {len(probe_output)} character(s)"
                )
            except asyncio.TimeoutError:
                log.debug(f"SSH probe {host}:{port}: probe command timeout for {plugin_cls.__name__}")

            try:
                log.debug(
                    f"SSH probe {host}:{port}: parsing {len(probe_output)} character(s) "
                    f"of probe output with {plugin_cls.__name__}"
                )
                probe_result = await asyncio.wait_for(
                    asyncio.to_thread(plugin_cls.parse_probe_output, probe_output),
                    timeout=self._PROBE_PARSE_TIMEOUT,
                )
                log.debug(
                    f"SSH probe {host}:{port}: {plugin_cls.__name__} parsed probe output "
                    f"as vendor={probe_result.vendor!r} model={probe_result.model!r} "
                    f"version={probe_result.version!r}"
                )
            except asyncio.TimeoutError:
                log.warning(
                    f"SSH probe {host}:{port}: probe output parsing timed out for "
                    f"{plugin_cls.__name__}"
                )
                continue
            except Exception as exc:
                log.warning(
                    f"SSH probe {host}:{port}: probe output parsing failed for "
                    f"{plugin_cls.__name__}: {exc}"
                )
                continue
            if probe_result.vendor:
                device_info = DeviceInfo(
                    vendor=probe_result.vendor,
                    model=probe_result.model,
                    version=probe_result.version,
                    hostname=probe_result.hostname,
                    serial_number=probe_result.serial_number,
                )
                log.debug(
                    f"SSH probe {host}:{port}: identified by {plugin_cls.__name__} "
                    f"as {device_info.vendor}/{device_info.model}/{device_info.version}"
                )
                return SshProbeResult(
                    success=True,
                    host=host,
                    port=port,
                    credential=credential,
                    device_info=device_info,
                    raw_output=welcome_output + "\n" + probe_output,
                )

        return SshProbeResult(
            success=True,
            host=host,
            port=port,
            credential=credential,
            device_info=None,
            raw_output=welcome_output,
        )

    async def _close_connection(
        self,
        conn: asyncssh.SSHClientConnection,
        host: str,
        port: int,
    ) -> None:
        """Close SSH connections without allowing cleanup to stall the worker."""
        try:
            conn.close()
            await asyncio.wait_for(
                conn.wait_closed(),
                timeout=self._CONNECTION_CLOSE_TIMEOUT,
            )
        except asyncio.TimeoutError:
            log.debug(
                f"SSH probe {host}:{port}: connection close timed out"
            )
        except Exception as exc:
            log.debug(
                f"SSH probe {host}:{port}: connection close failed: {exc}"
            )

    @staticmethod
    async def _emit_event(
        event_logger: ProbeEventLogger | None,
        step_code: str,
        step: str,
        status: str,
        message: str,
    ) -> None:
        if event_logger is None:
            return
        result = event_logger(step_code, step, status, message)
        if asyncio.iscoroutine(result):
            await result

    @staticmethod
    def _format_credential_label(credential: SshCredential) -> str:
        if credential.name:
            return f"SSH credential '{credential.name}' (user '{credential.username}')"
        return f"SSH user '{credential.username}'"

    @classmethod
    def _get_probe_prompt_pattern(cls, plugin_cls: type) -> re.Pattern:
        pattern_helper = getattr(plugin_cls, "PatternHelper", None)
        if pattern_helper is None:
            return cls._GENERIC_PROMPT_PATTERN
        get_union_pattern = getattr(pattern_helper, "get_union_pattern", None)
        if get_union_pattern is None:
            return cls._GENERIC_PROMPT_PATTERN
        return get_union_pattern()

    async def _read_until_prompt(self, process: asyncssh.SSHClientProcess, cmd: str, union_pattern: re.Pattern) -> str:
        """Read from process stdout until no more data arrives."""
        output = ReadBuffer(cmd)
        while process.stdout and not process.stdout.at_eof():
            try:
                chunk = await asyncio.wait_for(
                    process.stdout.read(4096),
                    timeout=self._READ_IDLE_TIMEOUT,
                )
            except asyncio.TimeoutError:
                log.debug(
                    f"SSH probe command {cmd!r}: read idle timeout, "
                    f"returning {len(output.get_data())} character(s) of partial output"
                )
                break
            if not chunk:
                break
            output.append(chunk)
            if output.check_pattern(union_pattern):
                break
        return output.get_data()
    
    async def _read_prompt(
        self,
        process: asyncssh.SSHClientProcess,
        prompt_pattern: re.Pattern | None = None,
    ) -> tuple[str, str]:
        """Read from process stdout until EOF."""
        output = ReadBuffer()
        effective_prompt_pattern = prompt_pattern or self._GENERIC_PROMPT_PATTERN
        try:
            while process.stdout and not process.stdout.at_eof():
                try:
                    chunk = await asyncio.wait_for(
                        process.stdout.read(1024),
                        timeout=self._READ_IDLE_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    log.debug(
                        "SSH probe: prompt read idle timeout, returning partial output"
                    )
                    break
                if not chunk:
                    break
                output.append(chunk)
                if output.check_pattern(effective_prompt_pattern):
                    break
        except Exception as exc:
            log.debug(f"SSH probe: error while reading until EOF: {exc}")
        log.debug(
            f"SSH probe: raw prompt output: "
            f"{self._format_output_preview(output.get_data())!r}"
        )
        # get last no-blank line as prompt
        lines = output.get_data().splitlines()
        num_lines = len(lines)
        for i in range(num_lines - 1, -1, -1):
            line = lines[i]
            if line.strip():
                return line.strip(), output.get_data()
        return "", output.get_data()

    @classmethod
    def _format_output_preview(cls, output: str) -> str:
        if len(output) <= cls._OUTPUT_PREVIEW_LIMIT:
            return output
        return output[: cls._OUTPUT_PREVIEW_LIMIT] + "...<truncated>"
