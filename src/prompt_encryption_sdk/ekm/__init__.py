"""Ekm package for exporting keying material."""

from .exporter import export_keying_material

# Explicitly export the main function
__all__ = ("export_keying_material",)
