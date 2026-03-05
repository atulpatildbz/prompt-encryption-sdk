from absl import flags


def pytest_configure(config):
   """Parse absl flags so test_tmpdir and other flags are available."""
   try:
       flags.FLAGS(['pytest'])
   except flags.DuplicateFlagError:
       pass
