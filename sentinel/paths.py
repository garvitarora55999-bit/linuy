"""Cross-platform path resolution for packaged and source-checkout executions."""

from __future__ import annotations

from sentinel import (
    PACKAGE_DIR,
    get_bundled_samples_dir,
    get_source_checkout_root,
    get_user_data_report_dir,
    is_installed_in_site_packages,
    is_safe_report_directory_path,
    resolve_default_report_dir,
)

__all__ = [
    "PACKAGE_DIR",
    "get_bundled_samples_dir",
    "get_source_checkout_root",
    "get_user_data_report_dir",
    "is_installed_in_site_packages",
    "is_safe_report_directory_path",
    "resolve_default_report_dir",
]
