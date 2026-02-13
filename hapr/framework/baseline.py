"""Load and manage YAML baseline definitions."""

from __future__ import annotations

import importlib.resources
import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


def load_baseline(path: str | Path | None = None) -> dict[str, Any]:
    """Load the HAPR baseline YAML and return the parsed dict.

    Parameters
    ----------
    path:
        Path to a custom baseline YAML.  When *None* the built-in
        split baseline (metadata + per-category check files) is used.
        Custom paths are always loaded as monolithic single files.
    """
    if path:
        return _load_single_file(Path(path))
    return _load_split_baseline()


def _load_single_file(p: Path) -> dict[str, Any]:
    """Load a monolithic baseline YAML from *p*."""
    if not p.exists():
        raise FileNotFoundError(f"Baseline file not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or "checks" not in data:
        raise ValueError(f"Invalid baseline file — missing 'checks' key: {p}")
    return data


def _load_split_baseline() -> dict[str, Any]:
    """Load the built-in split baseline (metadata + per-category files).

    The main ``hapr-baseline.yaml`` contains ``metadata`` and a
    ``check_files`` list.  Each referenced file is a bare YAML list of
    check dicts located under ``hapr.data.checks``.

    Falls back to monolithic loading if the main file still contains a
    ``checks`` key (backward compatibility).
    """
    ref = importlib.resources.files("hapr.data").joinpath("hapr-baseline.yaml")
    with importlib.resources.as_file(ref) as p:
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        raise ValueError("Invalid built-in baseline file")

    # Backward compat: if the monolithic file still has a 'checks' key, use it
    if "checks" in data:
        return data

    if "check_files" not in data:
        raise ValueError(
            "Built-in baseline missing both 'checks' and 'check_files' keys"
        )

    checks: list[dict[str, Any]] = []
    checks_pkg = importlib.resources.files("hapr.data.checks")
    for filename in data["check_files"]:
        ref = checks_pkg.joinpath(filename)
        with importlib.resources.as_file(ref) as fp:
            with fp.open("r", encoding="utf-8") as fh:
                file_checks = yaml.safe_load(fh)
        if not isinstance(file_checks, list):
            raise ValueError(f"Expected a YAML list in {filename}, got {type(file_checks).__name__}")
        checks.extend(file_checks)

    data["checks"] = checks
    del data["check_files"]
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
