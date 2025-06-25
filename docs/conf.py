"""Sphinx configuration for GxP Python Toolkit."""

import os
import sys
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(".."))

# Project information
project = "GxP Python Toolkit"
copyright = f"{datetime.now().year}, GxP Python Toolkit Contributors"
author = "GxP Python Toolkit Contributors"
release = "1.0.0"

# General configuration
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "sphinx_copybutton",
    "myst_parser",
    "sphinx_design",
]

# Autosummary settings
autosummary_generate = True
autosummary_imported_members = False


# Intersphinx mapping
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "sqlalchemy": ("https://docs.sqlalchemy.org/en/latest/", None),
    "pydantic": ("https://docs.pydantic.dev/latest/", None),
}

# Add any paths that contain templates here
templates_path = ["_templates"]

# List of patterns to ignore
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# HTML output options
html_theme = "furo"
html_static_path = ["_static"]
html_title = "GxP Python Toolkit"

html_theme_options = {
    "sidebar_hide_name": False,
    "navigation_with_keys": True,
    "top_of_page_button": "edit",
    "source_repository": "https://github.com/gxp-python-toolkit/gxp-python-toolkit",
    "source_branch": "main",
    "source_directory": "docs/",
}

# Copy button configuration
copybutton_prompt_text = r">>> |\.\.\. |\$ |In \[\d*\]: | {2,5}\.\.\.: | {5,8}: "
copybutton_prompt_is_regexp = True

# MyST parser configuration
myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "fieldlist",
    "html_admonition",
    "html_image",
    "replacements",
    "smartquotes",
    "substitution",
    "tasklist",
]

# Autodoc settings
autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "exclude-members": "__weakref__",
    "show-inheritance": True,
    "inherited-members": True,
    "autoclass_content": "both",  # Include both class and __init__ docstrings
}

autodoc_typehints = "both"
autodoc_typehints_format = "short"
autodoc_typehints_description_target = "documented"
autodoc_mock_imports = []

# Generate autosummary stubs
autosummary_generate = True
autosummary_generate_overwrite = True
autosummary_imported_members = False

# Napoleon settings for Google/NumPy style docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_preprocess_types = False
napoleon_type_aliases = None
napoleon_attr_annotations = True

# Todo extension settings
todo_include_todos = True
