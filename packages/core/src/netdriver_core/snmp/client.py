#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SNMP client for basic GET/WALK operations using pysnmp-lextudio."""

import asyncio

from pysnmp.hlapi.asyncio import (  # type: ignore[import]
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    getCmd,
    bulkCmd,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmDESPrivProtocol,
    usmAesCfb128Protocol,
)

from netdriver_core.log import logman
from netdriver_core.snmp.models import SnmpCredential, SnmpResult

log = logman.logger

# Standard MIB-II OIDs
SNMP_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysServices": "1.3.6.1.2.1.1.7.0",
}

# Auth protocol mapping
_AUTH_PROTOCOLS = {
    "md5": usmHMACMD5AuthProtocol,
    "sha": usmHMACSHAAuthProtocol,
}

# Priv protocol mapping
_PRIV_PROTOCOLS = {
    "des": usmDESPrivProtocol,
    "aes": usmAesCfb128Protocol,
    "aes128": usmAesCfb128Protocol,
}


class SnmpClient:
    """Async SNMP client wrapping pysnmp-lextudio."""

    _CLOSE_DRAIN_DELAY = 0.1

    def __init__(
        self,
        timeout: float = 5.0,
        retries: int = 1,
        port: int = 161,
        engine_pool_size: int = 50,
    ):
        self._timeout = timeout
        self._retries = retries
        self._port = port
        self._engine_pool_size = max(1, engine_pool_size)
        self._engine_pool: asyncio.Queue[SnmpEngine] = asyncio.Queue()
        self._created_engines = 0
        self._engines: list[SnmpEngine] = []
        self._closed = False

    async def get(
        self,
        host: str,
        credential: SnmpCredential,
        oids: list[str],
        port: int | None = None,
    ) -> SnmpResult:
        """SNMP GET operation.

        Args:
            host: Target IP address.
            credential: SNMP credential (v2c community or v3 user).
            oids: List of OID strings to query.

        Returns:
            SnmpResult with {oid: value} data on success.
        """
        auth_data = self._build_auth_data(credential)
        context = self._build_context_data(credential)
        transport = UdpTransportTarget(
            (host, port or self._port),
            timeout=self._timeout,
            retries=self._retries,
        )
        object_types = [ObjectType(ObjectIdentity(oid)) for oid in oids]
        engine = await self._acquire_engine()

        try:
            error_indication, error_status, error_index, var_binds = await getCmd(
                engine,
                auth_data,
                transport,
                context,
                *object_types,
            )
        except Exception as e:
            log.debug(f"SNMP GET failed for {host}: {e}")
            return SnmpResult(success=False, error=str(e))
        finally:
            self._release_engine(engine)

        if error_indication:
            return SnmpResult(success=False, error=str(error_indication))

        if error_status:
            error_msg = f"{error_status.prettyPrint()} at {var_binds[int(error_index) - 1][0] if error_index else '?'}"
            return SnmpResult(success=False, error=error_msg)

        data = {}
        for var_bind in var_binds:
            oid_str = str(var_bind[0])
            value_str = str(var_bind[1])
            data[oid_str] = value_str

        return SnmpResult(success=True, data=data)

    async def walk(
        self,
        host: str,
        credential: SnmpCredential,
        oid: str,
        port: int | None = None,
    ) -> SnmpResult:
        """SNMP WALK (GETBULK) operation.

        Args:
            host: Target IP address.
            credential: SNMP credential.
            oid: Root OID to walk.

        Returns:
            SnmpResult with {oid: value} data on success.
        """
        auth_data = self._build_auth_data(credential)
        context = self._build_context_data(credential)
        transport = UdpTransportTarget(
            (host, port or self._port),
            timeout=self._timeout,
            retries=self._retries,
        )
        data = {}
        engine = await self._acquire_engine()
        try:
            error_indication, error_status, error_index, var_bind_table = await bulkCmd(
                engine,
                auth_data,
                transport,
                context,
                0, 25,  # non-repeaters, max-repetitions
                ObjectType(ObjectIdentity(oid)),
            )

            if error_indication:
                return SnmpResult(success=False, error=str(error_indication))

            if error_status:
                return SnmpResult(success=False, error=str(error_status.prettyPrint()))

            for var_bind in var_bind_table:
                oid_str = str(var_bind[0])
                if not oid_str.startswith(oid):
                    break
                data[oid_str] = str(var_bind[1])

        except Exception as e:
            log.debug(f"SNMP WALK failed for {host}: {e}")
            return SnmpResult(success=False, error=str(e))
        finally:
            self._release_engine(engine)

        return SnmpResult(success=True, data=data)

    async def get_system_info(
        self,
        host: str,
        credential: SnmpCredential,
        port: int | None = None,
    ) -> SnmpResult:
        """Convenience method to get standard system info (sysDescr, sysObjectID, sysName).

        Args:
            host: Target IP address.
            credential: SNMP credential.

        Returns:
            SnmpResult with system info.
        """
        oids = [
            SNMP_OIDS["sysDescr"],
            SNMP_OIDS["sysObjectID"],
            SNMP_OIDS["sysName"],
        ]
        return await self.get(host, credential, oids, port=port)

    @staticmethod
    def _build_auth_data(credential: SnmpCredential):
        """Build pysnmp auth data from credential."""
        if credential.version == "v1":
            return CommunityData(credential.community or "public", mpModel=0)
        if credential.version == "v2c":
            return CommunityData(credential.community or "public", mpModel=1)

        # SNMPv3
        auth_proto = _AUTH_PROTOCOLS.get(
            (credential.auth_protocol or "").lower()
        )
        priv_proto = _PRIV_PROTOCOLS.get(
            (credential.priv_protocol or "").lower()
        )

        return UsmUserData(
            userName=credential.username or "",
            authKey=credential.auth_password,
            privKey=credential.priv_password,
            authProtocol=auth_proto,
            privProtocol=priv_proto,
        )

    @staticmethod
    def _build_context_data(credential: SnmpCredential) -> ContextData:
        """Build SNMP context data, including optional SNMPv3 context name."""
        return ContextData(contextName=credential.context_name or "")

    async def aclose(self) -> None:
        """Close the underlying dispatcher after pending datagram callbacks drain."""
        await asyncio.sleep(self._CLOSE_DRAIN_DELAY)
        self.close()

    def close(self) -> None:
        """Close the underlying dispatcher."""
        if self._closed:
            return
        self._closed = True
        for engine in self._engines:
            self._close_engine_dispatcher(engine)

    async def _acquire_engine(self) -> SnmpEngine:
        """Borrow an SNMP engine from the lazy bounded pool."""
        if self._closed:
            raise RuntimeError("SNMP client is closed")
        try:
            return self._engine_pool.get_nowait()
        except asyncio.QueueEmpty:
            pass

        if self._created_engines < self._engine_pool_size:
            engine = SnmpEngine()
            self._created_engines += 1
            self._engines.append(engine)
            return engine

        return await self._engine_pool.get()

    def _release_engine(self, engine: SnmpEngine) -> None:
        """Return an SNMP engine to the pool unless the client is closing."""
        if self._closed:
            self._close_engine_dispatcher(engine)
            return
        self._engine_pool.put_nowait(engine)

    @staticmethod
    def _close_engine_dispatcher(engine: SnmpEngine) -> None:
        """Close pysnmp dispatcher tasks so worker shutdown does not leak pending coroutines."""
        try:
            engine.closeDispatcher()
        except Exception as exc:
            log.debug(f"Failed to close SNMP dispatcher cleanly: {exc}")
