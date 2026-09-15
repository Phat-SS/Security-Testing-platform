"""Server-rendered HTML views (dependency-free, theme-aware).

One module per screen, plus `assessment/` and `config/` for the two screens big
enough to need a package of their own. Kept separate from routing: everything
shown here has passed secret redaction upstream (executions/findings) or is
non-secret metadata.

`from app.api import views` reaches every page builder a route needs, which is
what the split preserved — the routes did not change when this stopped being
one 1600-line module.
"""

from __future__ import annotations

from .assessment import body as assessment_body  # noqa: F401
from .activity import activity_page
from .assessment_page import assessment_page
from .config import config_page, resolve_config_tab
from .dashboard import dashboard
from .errors import error_page
from .findings import findings_page
from .login import login_page
from .regression import comment_preview_page, regression_page
from .shell import appbar, configure, page, set_chrome
from .test_detail import test_detail_page

__all__ = [
    "appbar",
    "activity_page",
    "assessment_page",
    "comment_preview_page",
    "config_page",
    "configure",
    "dashboard",
    "error_page",
    "findings_page",
    "login_page",
    "page",
    "regression_page",
    "resolve_config_tab",
    "set_chrome",
    "test_detail_page",
]
