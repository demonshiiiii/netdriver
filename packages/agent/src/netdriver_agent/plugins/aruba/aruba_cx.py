#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from netdriver_agent.plugins.aruba.aruba import ArubaBase
from netdriver_core.plugin.plugin_info import PluginInfo


class ArubaCX(ArubaBase):
    """ Aruba CX Plugin """

    info = PluginInfo(
        vendor="aruba",
        model="cx",
        version="base",
        description="Aruba CX Plugin"
    )