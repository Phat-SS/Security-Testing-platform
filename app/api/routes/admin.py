"""Shutting the platform down.

The most destructive action the app can take, so it carries a role check, a
confirmation header, and a confirm() in the UI.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path

import psutil
from fastapi import APIRouter, Depends, Header, HTTPException

from app.api.deps import require
from app.core.auth import User

logger = logging.getLogger(__name__)

router = APIRouter()


# -- shutdown -----------------------------------------------------------


# Everything this project runs (this server, the demo vulnerable target, stray
# CLI/pytest runs) does so through the project's own virtualenv interpreter, so
# "process uses an exe path under this .venv" is a precise, safe way to find
# *only* this project's processes — never an unrelated python process.
#
# parents[3], not a chain of `.parent`: this file is app/api/routes/admin.py,
# one level deeper than the app/api/main.py it was cut from. Keeping the old
# expression pointed it at app/.venv, which does not exist — so the sweep
# matched nothing and shutdown killed only this process while the confirm
# dialog promised it had stopped the rest. Pinned by a test below.
_VENV_DIR = Path(__file__).resolve().parents[3] / ".venv"


def _project_processes() -> list[psutil.Process]:
    try:
        venv_dir = _VENV_DIR.resolve()
    except OSError:
        return []
    matched: dict[int, psutil.Process] = {}
    for proc in psutil.process_iter(["pid", "exe"]):
        try:
            exe = proc.info.get("exe") or ""
            if exe and Path(exe).resolve().is_relative_to(venv_dir):
                matched[proc.pid] = proc
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
            continue
    # On Windows this venv's python.exe is itself a launcher stub that spawns
    # the real base interpreter as a *child* process — the child is the one
    # that actually holds the listening socket, and its own exe path is the
    # base install, not this venv, so it would never match above. Sweep
    # descendants of every match so the real worker is never left behind.
    for proc in list(matched.values()):
        try:
            for child in proc.children(recursive=True):
                matched[child.pid] = child
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return list(matched.values())


def _shutdown_everything(other_procs: list[psutil.Process]) -> None:
    time.sleep(0.4)  # let the HTTP response below reach the browser first
    for p in other_procs:
        try:
            p.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    _, alive = psutil.wait_procs(other_procs, timeout=3)
    for p in alive:
        try:
            p.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    os._exit(0)  # this process last, unconditionally — a hard stop, not a request


@router.post("/admin/shutdown")
async def shutdown(
    x_confirm_shutdown: str | None = Header(None),
    user: User = Depends(require("admin")),
):
    # This kills every process on the machine running under this project's
    # venv — the most destructive single action the platform can take.
    # require("admin") (not "tester") plus a custom header the dashboard's
    # own fetch() sets are both defense-in-depth on top of the global CSRF
    # guard above: a plain cross-site <form> cannot set a custom header at
    # all (doing so from script triggers a CORS preflight this server never
    # approves), so this can only be reached from the dashboard button.
    if x_confirm_shutdown != "security-testing-platform-ui":
        raise HTTPException(
            status_code=400,
            detail="Missing confirmation header; use the dashboard's Shutdown server button.",
        )
    others = [p for p in _project_processes() if p.pid != os.getpid()]
    threading.Thread(target=_shutdown_everything, args=(others,), daemon=True).start()
    return {"status": "shutting down", "other_processes_stopped": len(others)}
