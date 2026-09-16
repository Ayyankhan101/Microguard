"""The test environment cannot reach a real tracking backend.

Guards the autouse fixture in conftest.py. Without it, a developer with
Databricks credentials had their test runs logged to their real workspace
(see `_no_real_tracking_backend`).
"""

import os
from pathlib import Path


class TestNoRealTrackingBackend:
    def test_no_databricks_credentials_are_visible(self):
        leaked = [
            name for name in os.environ
            if name.startswith("DATABRICKS_") and name != "DATABRICKS_CONFIG_FILE"
        ]
        assert leaked == []

    def test_no_mlflow_tracking_uri_is_inherited(self):
        assert "MLFLOW_TRACKING_URI" not in os.environ
        assert "MLFLOW_REGISTRY_URI" not in os.environ

    def test_the_databricks_config_file_does_not_exist(self):
        """With no env vars the SDK falls back to ~/.databrickscfg; that
        fallback has to be closed off too."""
        assert not Path(os.environ["DATABRICKS_CONFIG_FILE"]).exists()
