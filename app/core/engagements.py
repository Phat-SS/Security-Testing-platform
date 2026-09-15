"""More than one engagement, without more than one process.

An engagement is the authorized testing context for one client: the approved
target, the scope, the identities. There was exactly one, loaded from one file
path, held as a process-global — so a consultancy testing three clients ran
three copies of the platform, and a tester with two tickets open in two tabs
could point a run at the wrong target by saving the wrong config.

**Engagements stay files.** The authorization boundary is meant to be read,
diffed and attached to a ticket; a row in a database is none of those things.
So this is a directory of the same JSON documents, discovered by name:

    config/engagements/bmw-au.json     -> "bmw-au"
    config/engagements/acme.json       -> "acme"

The single `config/engagement.json` an existing install already has keeps
working and appears under its own name, so nothing has to be moved to upgrade.

**Which one is current is per request, never global.** An assessment records
the engagement it belongs to and always resolves to that one; screens that are
not about a particular assessment use the tester's own selection. Two requests
in flight get their own answer — the reason the previous arrangement could
aim a run at the wrong target is that they did not.
"""

from __future__ import annotations

import contextvars
import os
import re
from pathlib import Path

from app.core.engagement import Engagement, load_engagement

#: The name a single-file install appears under. Not "default" — that is also a
#: plausible name for a real engagement, and the two must not collide.
LEGACY_NAME = "engagement"

#: Names are file stems and a path segment in `?engagement=`, so the same rule
#: the environment names follow: letters, digits, spaces, `-` and `_`.
_VALID_NAME = re.compile(r"^[A-Za-z0-9 _-]{1,64}$")


#: Where a written engagement lands when nothing says otherwise. Used as a write
#: target, never as a thing to discover — see `discover`.
DEFAULT_DIR = "config/engagements"
DEFAULT_FILE = "config/engagement.json"


def directory() -> Path:
    return Path(os.getenv("ENGAGEMENTS_DIR", "") or DEFAULT_DIR)


def legacy_path() -> Path:
    return Path(os.getenv("ENGAGEMENT_CONFIG", "") or DEFAULT_FILE)


def is_valid_name(name: str) -> bool:
    return bool(_VALID_NAME.match(name or ""))


def discover() -> dict[str, Path]:
    """Every engagement this process was pointed at, by name.

    **Nothing is discovered unless an environment variable names it.** Default
    deny is the platform's first rule: an empty configuration means nothing is
    in scope and no persona exists, so no test can run until a human has said
    where the authorization lives. A directory of config files happening to
    exist on disk beside the code is not a human saying so — it is how a
    checkout of the repository, or a stale file from another engagement, comes
    to authorize a run nobody asked for.

    `ENGAGEMENTS_DIR` opts into the directory; `ENGAGEMENT_CONFIG` opts into a
    single file, which is what every existing install already sets. Neither is
    set: no engagements, and the empty one every caller gets back cannot run
    anything.

    The single file is added last so a directory entry of the same name wins —
    an install that has migrated should not keep seeing the old file.
    """
    found: dict[str, Path] = {}
    if os.getenv("ENGAGEMENTS_DIR", "").strip():
        folder = directory()
        if folder.is_dir():
            for path in sorted(folder.glob("*.json")):
                if is_valid_name(path.stem):
                    found[path.stem] = path
    if os.getenv("ENGAGEMENT_CONFIG", "").strip():
        legacy = legacy_path()
        if legacy.exists() and legacy.stem not in found:
            found.setdefault(LEGACY_NAME, legacy)
    return found


class Registry:
    """The loaded engagements, and which one this request is about.

    Loads are cached because `load_engagement` reads and parses a file and the
    sidebar asks for the current one on every page. `reload` is what every
    config writer calls after saving, so the cache can never be the reason a
    tester sees a setting they just changed fail to take effect — which was the
    class of bug that made `set_designer` necessary in the first place.
    """

    def __init__(self) -> None:
        self._loaded: dict[str, Engagement] = {}
        self._paths: dict[str, Path] = {}
        self._current: contextvars.ContextVar[str] = contextvars.ContextVar(
            "current_engagement", default=""
        )
        self.refresh()

    # -- what exists --------------------------------------------------------

    def refresh(self) -> None:
        """Re-scan the directory. Cheap, and the only way a file added by hand
        while the server is running becomes visible."""
        self._paths = discover()
        for name in list(self._loaded):
            if name not in self._paths:
                del self._loaded[name]

    def names(self) -> list[str]:
        return sorted(self._paths)

    def exists(self, name: str) -> bool:
        return name in self._paths

    def path(self, name: str = "") -> str:
        """Where this engagement's file is — the write target for the config UI.

        An unknown name resolves to where it *would* live, so saving into a
        fresh engagement creates it rather than failing. That is how the first
        one gets written on an install that has no config at all.
        """
        name = name or self.current_name
        known = self._paths.get(name)
        if known is not None:
            return str(known)
        if name == LEGACY_NAME:
            return str(legacy_path())
        return str(directory() / f"{name}.json")

    # -- which one ----------------------------------------------------------

    @property
    def default_name(self) -> str:
        names = self.names()
        if LEGACY_NAME in names:
            return LEGACY_NAME
        return names[0] if names else LEGACY_NAME

    @property
    def current_name(self) -> str:
        return self._current.get() or self.default_name

    def select(self, name: str) -> str:
        """Set the engagement for THIS request. Returns what was actually
        selected — an unknown name falls back rather than leaving the request
        pointed at nothing, because every screen needs an answer."""
        chosen = name if name and self.exists(name) else self.default_name
        self._current.set(chosen)
        return chosen

    # -- the engagement itself ----------------------------------------------

    def get(self, name: str = "") -> Engagement:
        """The loaded engagement, or the empty one.

        Reading and writing resolve differently on purpose. `path` answers
        "where would this live", so a save can create a file that does not
        exist yet. This answers "what is authorized", and a name nothing
        pointed at authorizes nothing — returning the empty engagement rather
        than reading a file off disk because it happened to be there is the
        same default-deny rule `discover` states.
        """
        name = name or self.current_name
        if not self.exists(name):
            return load_engagement("")
        if name not in self._loaded:
            self._loaded[name] = load_engagement(self.path(name))
        return self._loaded[name]

    @property
    def current(self) -> Engagement:
        return self.get()

    def adopt(self, name: str = "") -> None:
        """Register an engagement this process was not started with.

        Saving through the configuration UI is itself the deliberate act
        default-deny asks for — a human just said, in the product, where this
        engagement's authorization lives. Without this the file they wrote would
        be invisible until the next restart, and `discover` is deliberately not
        allowed to pick it up on its own.
        """
        name = name or self.current_name
        path = Path(self.path(name))
        if path.exists():
            self._paths[name] = path

    def reload(self, name: str = "") -> Engagement:
        name = name or self.current_name
        self.refresh()
        # After `refresh`, because refresh drops anything discovery no longer
        # sees — including the file a save just created.
        self.adopt(name)
        self._loaded.pop(name, None)
        return self.get(name)

    def describe(self, name: str = "") -> str:
        """One line for a picker: the target this engagement points at."""
        engagement = self.get(name or self.current_name)
        active = engagement.active_environment or ""
        url = engagement.environments.get(active, engagement.target_base_url)
        return url or ""
