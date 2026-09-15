"""The assessment screen, one module per phase.

`body()` is the only name anything outside this package uses; it lives in
`shell`, which assembles the four phases around the page chrome.
"""

from __future__ import annotations

from .shell import body

__all__ = ["body"]
