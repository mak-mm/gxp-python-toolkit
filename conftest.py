"""Pytest configuration for GxP Python Toolkit."""

import pytest


def pytest_collection_modifyitems(config, items):
    """Modify collection to skip certain items."""
    # No modifications needed for now
    pass


def pytest_configure(config):
    """Configure pytest with custom settings."""
    # Add custom markers
    config.addinivalue_line("markers", "gxp: mark test as GxP compliance test")


# Configure pytest to ignore certain warnings
pytest.mark.filterwarnings("ignore::pytest.PytestCollectionWarning")
