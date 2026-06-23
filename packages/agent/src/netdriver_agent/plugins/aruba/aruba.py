#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from netdriver_core.dev.mode import Mode
from netdriver_core.plugin.plugin_info import PluginInfo
from netdriver_agent.plugins.base import Base

# pylint: disable=abstract-method
class ArubaBase(Base):
    """ Aruba Base Plugin """

    info = PluginInfo(
        vendor="aruba",
        model="base",
        version="base",
        description="Aruba Base Plugin"
    )

    _CMD_CANCEL_MORE = "no page"

    def get_union_pattern(self) -> re.Pattern:
        return ArubaBase.PatternHelper.get_union_pattern()

    def get_error_patterns(self) -> list[re.Pattern]:
        return ArubaBase.PatternHelper.get_error_patterns()

    def get_ignore_error_patterns(self) -> list[re.Pattern]:
        return ArubaBase.PatternHelper.get_ignore_error_patterns()

    def get_enable_password_prompt_pattern(self) -> re.Pattern:
        return ArubaBase.PatternHelper.get_enable_password_prompt_pattern()

    def get_mode_prompt_patterns(self) -> dict[Mode, re.Pattern]:
        return {
            Mode.LOGIN: ArubaBase.PatternHelper.get_login_prompt_pattern(),
            Mode.ENABLE: ArubaBase.PatternHelper.get_enable_prompt_pattern(),
            Mode.CONFIG: ArubaBase.PatternHelper.get_config_prompt_pattern()
        }

    def get_more_pattern(self) -> tuple[re.Pattern, str]:
        return (ArubaBase.PatternHelper.get_more_pattern(), self._CMD_MORE)

    class PatternHelper:
        """ Inner class for patterns """
        # hostname> $
        _PATTERN_LOGIN = r"^\r{0,1}[^\s<]+>\s*$"
        # hostname# $
        _PATTERN_ENABLE = r"^\r{0,1}[^\s#]+#\s*$"
        # hostname(config)# $
        _PATTERN_CONFIG = r"^\r{0,1}\S+\(\S+\)#\s*$"
        _PATTERN_ENABLE_PASSWORD = r"[Pp]assword:"
        #  -- MORE -- 
        _PATTERN_MORE = r" -- MORE --"

        @staticmethod
        def get_login_prompt_pattern() -> re.Pattern:
            return re.compile(ArubaBase.PatternHelper._PATTERN_LOGIN, re.MULTILINE)

        @staticmethod
        def get_enable_prompt_pattern() -> re.Pattern:
            return re.compile(ArubaBase.PatternHelper._PATTERN_ENABLE, re.MULTILINE)

        @staticmethod
        def get_config_prompt_pattern() -> re.Pattern:
            return re.compile(ArubaBase.PatternHelper._PATTERN_CONFIG, re.MULTILINE)

        @staticmethod
        def get_union_pattern() -> re.Pattern:
            return re.compile(
                "(?P<login>{})|(?P<config>{})|(?P<enable>{})".format(
                    ArubaBase.PatternHelper._PATTERN_LOGIN,
                    ArubaBase.PatternHelper._PATTERN_CONFIG,
                    ArubaBase.PatternHelper._PATTERN_ENABLE
                ),
                re.MULTILINE
            )

        @staticmethod
        def get_enable_password_prompt_pattern() -> re.Pattern:
            return re.compile(ArubaBase.PatternHelper._PATTERN_ENABLE_PASSWORD, re.MULTILINE)

        @staticmethod
        def get_error_patterns() -> list[re.Pattern]:
            regex_strs = [
                r"Invalid input: .+"
            ]
            return [re.compile(regex_str, re.MULTILINE) for regex_str in regex_strs]

        @staticmethod
        def get_ignore_error_patterns() -> list[re.Pattern]:
            regex_sts = []
            return [re.compile(regex_str, re.MULTILINE) for regex_str in regex_sts]

        @staticmethod
        def get_more_pattern() -> re.Pattern:
            return re.compile(ArubaBase.PatternHelper._PATTERN_MORE, re.MULTILINE)