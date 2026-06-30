#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from netdriver_core.plugin.plugin_info import PluginInfo
from netdriver_agent.plugins.h3c import H3CBase


class H3CSR(H3CBase):
    """ H3C SR Plugin """

    info = PluginInfo(
        vendor="h3c",
        model="sr",
        version="base",
        description="H3C SR Plugin"
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.register_hooks()

    def register_hooks(self):
        """ Register hooks for specific commands """
        self.register_hook("save", self.save)