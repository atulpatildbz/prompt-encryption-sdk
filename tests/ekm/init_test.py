"""Tests for prompt_encryption_sdk.ekm.__init__."""

from prompt_encryption_sdk import ekm
from prompt_encryption_sdk.ekm import exporter

from absl.testing import absltest as googletest


class InitTest(googletest.TestCase):

  def test_exposes_export_keying_material(self) -> None:
    """Verifies that ekm.export_keying_material points to the correct function."""
    with self.subTest("HasAttr"):
      self.assertTrue(hasattr(ekm, "export_keying_material"))
    with self.subTest("IsCorrectFunction"):
      self.assertIs(ekm.export_keying_material, exporter.export_keying_material)
    with self.subTest("IsCallable"):
      self.assertTrue(callable(ekm.export_keying_material))


if __name__ == "__main__":
  googletest.main()
