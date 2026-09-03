"""Toy policy namespace for prompt-extraction examples."""

from . import CTLProperty, register_policy_module


TOOL_SIGNATURES = {
    "go_to_park": ["person"],
    "get_ice_cream": ["person"],
    "go_home": ["person"],
    "do_homework": ["person"],
}


SIDE_EFFECT_TOOLS = set(TOOL_SIGNATURES)


TOY_CTL_PROPERTIES: list[CTLProperty] = []


GENERIC_PROPERTIES: list[CTLProperty] = []


import sys
register_policy_module("toy", sys.modules[__name__])
