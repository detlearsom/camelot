# CTL Properties Class

from typing import List, Dict, Set
from dataclasses import dataclass


@dataclass
class CTLProperty:
    name: str
    formula: str
    description: str
    suite: str
    severity: str


ALL_PROPERTIES: Dict[str, List[CTLProperty]] = {}  # Placeholder
GENERIC_PROPERTIES: List[CTLProperty] = []


def get_properties_for_suite(suite_name: str, include_generic: bool = True) -> List[CTLProperty]:
    properties = ALL_PROPERTIES.get(suite_name, []).copy()

    if include_generic:
        properties.extend(GENERIC_PROPERTIES)
    return properties


def generate_nuxmv_spec(properties: List[CTLProperty]) -> str:
    lines = []
    lines.append("-- CTL Specifications")
    lines.append("")
    for prop in properties:
        lines.append(f"-- {prop.name}: {prop.description}")
        lines.append(f"-- Severity: {prop.severity}")
        lines.append(f"CTLSPEC {prop.formula};")
        lines.append("")

    return "\n".join(lines)


def save_spec(properties: List[CTLProperty], output_file: str) -> None:
    spec_text = generate_nuxmv_spec(properties)
    with open(output_file, "w") as f:
        f.write(spec_text)
