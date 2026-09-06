"""BlockWill fork: runtime patches for upstream plane-sdk bugs.

Applied once at server startup (see server.py). Each patch is idempotent and
guarded so it becomes a no-op automatically once the SDK is fixed upstream —
delete a patch here when its guard stops matching after an SDK bump.
"""

from __future__ import annotations

import typing

from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


def _patch_activity_epoch() -> None:
    """plane-sdk 0.2.23 types WorkItemActivity.epoch as `int`, but Plane returns
    a float unix timestamp (e.g. 1787552183.322), so every workitem_activity
    list/retrieve call fails pydantic validation. Widen the field to accept
    floats and rebuild the affected models (the paginated parent embeds a
    snapshot of the child schema, so it must be rebuilt too).
    """
    try:
        from plane.models.work_items import (
            PaginatedWorkItemActivityResponse,
            WorkItemActivity,
        )
    except Exception:  # SDK shape changed
        logger.warning("plane-sdk activity models not found; epoch patch skipped")
        return

    field = WorkItemActivity.model_fields.get("epoch")
    if field is None:
        return
    args = typing.get_args(field.annotation)
    # Only patch the exact bug shape (int, not already float). No-op once fixed.
    if int not in args or float in args:
        return

    field.annotation = float | None
    WorkItemActivity.model_rebuild(force=True)
    PaginatedWorkItemActivityResponse.model_rebuild(force=True)
    logger.info("Applied plane-sdk patch: WorkItemActivity.epoch accepts float")


def apply_sdk_patches() -> None:
    """Apply every fork-local SDK patch. Safe to call more than once."""
    _patch_activity_epoch()
