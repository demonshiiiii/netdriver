#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Load device type mappings from a single YAML configuration."""

from functools import lru_cache
import os
from pathlib import Path
import re
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict
import yaml

from netdriver_core.log import logman


log = logman.logger

_AGENT_CONFIG_ENV_VAR = "NETDRIVER_AGENT_CONFIG"
_DEVICE_TYPE_MAP_VAR = "NETDRIVER_DISCOVERY_DEVICE_TYPE_MAP"


class DeviceTypeRule(BaseModel):
    """A single SSH discovery parse rule."""

    model_config = ConfigDict(extra="forbid")

    pattern: str
    dev_type: str
    compiled: Optional[re.Pattern] = None

    def model_post_init(self, __context: Any) -> None:
        if self.pattern:
            self.compiled = re.compile(self.pattern, re.IGNORECASE)

    def match(self, model: str) -> bool:
        return bool(self.compiled and self.compiled.search(model))


def _iter_candidate_paths(*, env_var: str, default_name: str) -> list[Path]:
    candidates: list[Path] = []
    explicit_path = os.getenv(env_var)
    if explicit_path:
        candidates.append(Path(explicit_path).expanduser())

    agent_config_path = os.getenv(_AGENT_CONFIG_ENV_VAR)
    if agent_config_path:
        candidates.append(Path(agent_config_path).expanduser().parent / default_name)

    candidates.append(Path("config/agent") / default_name)
    return candidates

def _load_config_text(*, env_var: str, default_name: str) -> tuple[str, str]:
    for candidate in _iter_candidate_paths(env_var=env_var, default_name=default_name):
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8"), str(candidate)

    explicit_path = os.getenv(env_var)
    if explicit_path:
        log.warning("Discovery device type map file '%s' not found", explicit_path)

    return "", ""

def reset_device_type_map_cache() -> None:
    """Reset cached device type map configuration."""
    _load_device_type_map.cache_clear()


@lru_cache(maxsize=1)
def _load_device_type_map() -> dict[str, list[DeviceTypeRule]]:
    """Load device type map from YAML."""
    config_text, config_source = _load_config_text(env_var=_DEVICE_TYPE_MAP_VAR, default_name="device_type_map.yml")
    if not config_text:
        return {}

    config = yaml.safe_load(config_text)
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError(f"invalid discovery parse rule format from {config_source}")

    normalized_rules: dict[str, list[DeviceTypeRule]] = {}
    for vendor, patterns in config.items():
        normalized_rules[vendor] = []
        for pattern, dev_type in patterns.items():
            normalized_rules[vendor].append(DeviceTypeRule(pattern=pattern, dev_type=dev_type))
    
    log.debug(
        f"Loaded device type map from {config_source} "
        f"with {len(normalized_rules)} vendor entries"
    )
    return normalized_rules


def get_device_type(vendor: str, model: str) -> str:
    if vendor and model:
        rules_map = _load_device_type_map()
        if rules_map: 
            rules = rules_map.get(vendor, [])
            for rule in rules:
                if rule.match(model):
                    return rule.dev_type
    return "unknown"