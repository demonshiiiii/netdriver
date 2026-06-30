#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from netdriver_core.plugin.plugin_info import PluginInfo
from netdriver_agent.plugins.huawei import HuaweiBase


class HuaweiNetEngine(HuaweiBase):
    """ Huawei NetEngine Plugin """
    info = PluginInfo(
        vendor="huawei",
        model="netengine",
        version="base",
        description="Huawei NetEngine Plugin"
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.register_hooks()

    def register_hooks(self):
        """ Register hooks for specific commands """
        self.register_hook("save", self.save)