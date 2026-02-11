"""Check registry — imports all check modules so they are discoverable."""

from . import (  # noqa: F401
    access,
    backend,
    cve,
    disclosure,
    frontend,
    global_defaults,
    headers,
    logging_checks,
    process,
    request,
    timeouts,
    tls,
    tls_live,
)
