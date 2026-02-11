"""Load and manage YAML baseline definitions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# Default baseline path (relative to project root)
_DEFAULT_BASELINE = Path(__file__).resolve().parent.parent.parent / "framework" / "hapr-baseline.yaml"


def load_baseline(path: str | Path | None = None) -> dict[str, Any]:
    """Load the HAPR baseline YAML and return the parsed dict.

    Parameters
    ----------
    path:
        Path to a custom baseline YAML.  When *None* the built-in
        ``framework/hapr-baseline.yaml`` is used.
    """
    p = Path(path) if path else _DEFAULT_BASELINE
    if not p.exists():
        raise FileNotFoundError(f"Baseline file not found: {p}")

    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict) or "checks" not in data:
        raise ValueError(f"Invalid baseline file — missing 'checks' key: {p}")

    return data


def get_checks(baseline: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the list of check definitions from a loaded baseline."""
    return baseline.get("checks", [])


def get_checks_by_category(baseline: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Group check definitions by category."""
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for check in get_checks(baseline):
        cat = check.get("category", "unknown")
        by_cat.setdefault(cat, []).append(check)
    return by_cat


def get_check_by_id(baseline: dict[str, Any], check_id: str) -> dict[str, Any] | None:
    """Look up a single check definition by its ID."""
    for check in get_checks(baseline):
        if check.get("id") == check_id:
            return check
    return None


def get_categories(baseline: dict[str, Any]) -> list[str]:
    """Return sorted unique category names."""
    cats = {c.get("category", "unknown") for c in get_checks(baseline)}
    return sorted(cats)
