#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from dependency_injector.containers import DeclarativeContainer
from dependency_injector.providers import Factory, Singleton, Configuration
from netdriver_agent.handlers.cmd_req_handler import CommandRequestHandler
from netdriver_agent.handlers.conn_req_handler import ConnectRequestHandler
from netdriver_agent.handlers.discovery_handler import DiscoveryRequestHandler
from netdriver_agent.discovery.engine.discovery_engine import DiscoveryEngine
from netdriver_agent.discovery.engine.task_store import TaskStore
from netdriver_agent.security.secret_decryption import create_secret_decryptor


class Container(DeclarativeContainer):
    """ IoC container of netdriver agent. """
    config = Configuration()
    cmd_req_handler = Factory(CommandRequestHandler)
    conn_req_handler = Factory(ConnectRequestHandler)
    secret_decryptor = Factory(
        create_secret_decryptor,
        enabled=config.secrets.decrypt_enabled,
        encryption_key=config.secrets.encryption_key,
    )
    task_store = Singleton(
        TaskStore,
        db_path=config.discovery.db_path,
    )
    discovery_engine = Singleton(
        DiscoveryEngine,
        task_store=task_store,
        db_path=config.discovery.db_path,
        nmap_path=config.discovery.nmap_path,
        max_concurrent_probes=config.discovery.max_concurrent_probes,
        probe_timeout=config.discovery.probe_timeout,
        ssh_connect_timeout=config.discovery.ssh.connect_timeout,
        ssh_read_timeout=config.discovery.ssh.read_timeout,
        snmp_timeout=config.discovery.snmp.timeout,
        snmp_retries=config.discovery.snmp.retries,
        parse_rule_result_mode=config.discovery.parse_rule_result_mode,
        plugin_modules=["netdriver_agent.plugins"],
    )
    discovery_handler = Factory(
        DiscoveryRequestHandler,
        engine=discovery_engine,
        task_store=task_store,
        max_tasks=config.discovery.task.max_tasks,
        snmp_retries=config.discovery.snmp.retries,
        secret_decryptor=secret_decryptor,
    )


def get_config_file() -> str:
    """Get config file path from environment variable or use default."""
    return os.getenv("NETDRIVER_AGENT_CONFIG", "config/agent/agent.yml")


def configure_discovery_vendor_map() -> None:
    """Export discovery vendor map config for subprocess workers."""
    vendor_map_file = container.config.discovery.vendor_map_file()
    if vendor_map_file:
        os.environ["NETDRIVER_DISCOVERY_VENDOR_MAP"] = vendor_map_file
    else:
        os.environ.pop("NETDRIVER_DISCOVERY_VENDOR_MAP", None)

    snmp_parse_rules_file = container.config.discovery.snmp_parse_rules_file()
    if snmp_parse_rules_file:
        os.environ["NETDRIVER_DISCOVERY_SNMP_PARSE_RULES"] = snmp_parse_rules_file
    else:
        os.environ.pop("NETDRIVER_DISCOVERY_SNMP_PARSE_RULES", None)

    ssh_parse_rules_file = container.config.discovery.ssh_parse_rules_file()
    if ssh_parse_rules_file:
        os.environ["NETDRIVER_DISCOVERY_SSH_PARSE_RULES"] = ssh_parse_rules_file
    else:
        os.environ.pop("NETDRIVER_DISCOVERY_SSH_PARSE_RULES", None)

    ingest_rules_file = container.config.discovery.ingest_rules_file()
    if ingest_rules_file:
        os.environ["NETDRIVER_DISCOVERY_INGEST_RULES"] = ingest_rules_file
    else:
        os.environ.pop("NETDRIVER_DISCOVERY_INGEST_RULES", None)


container = Container()
container.config.from_yaml(get_config_file())
configure_discovery_vendor_map()
