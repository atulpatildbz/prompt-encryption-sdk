# //depot/google3/third_party/py/prompt_encryption_sdk/setup.py
"""Setup file for the prompt_encryption_sdk package."""

import fileinput
import pathlib
import subprocess
import sys
from setuptools import Extension, find_packages, setup
from setuptools.command.build_ext import build_ext
from setuptools.command.build_py import build_py

# Base directory of the package
BASE_DIR = pathlib.Path(__file__).resolve().parent
SRC_DIR = BASE_DIR / "src"

# Proto files and paths
PKG_NAME = "prompt_encryption_sdk"
PROTO_DIR = SRC_DIR / PKG_NAME / "proto"
PROTO_FILE_NAME = "attestation.proto"
PROTO_FILES = [str(PROTO_DIR / PROTO_FILE_NAME)]
PB2_GRPC_FILE = PROTO_DIR / "attestation_pb2_grpc.py"
PROTO_BASENAME = "attestation_pb2"


def patch_grpc_import() -> None:
  """Patches the generated _pb2_grpc.py to use relative imports, preserving indentation."""
  try:
    print(f"Patching imports in {PB2_GRPC_FILE}")
    with fileinput.input(PB2_GRPC_FILE, inplace=True) as f:
      for line in f:
        stripped_line = line.strip()
        if stripped_line.startswith(f"import {PROTO_BASENAME} as"):
          new_line = line.replace(
              f"import {PROTO_BASENAME} as", f"from . import {PROTO_BASENAME} as"
          )
          print(new_line, end="")
        else:
          print(line, end="")
    print(f"Finished patching {PB2_GRPC_FILE}")
  except FileNotFoundError:
    print(f"Warning: {PB2_GRPC_FILE} not found, skipping patch.")


def compile_protos() -> None:
  """Compiless .proto files to _pb2.py and _pb2_grpc.py.."""
  protoc_command = [
      sys.executable,
      "-m",
      "grpc_tools.protoc",
      f"-I{PROTO_DIR}",
      f"--python_out={PROTO_DIR}",
      f"--grpc_python_out={PROTO_DIR}",
  ] + PROTO_FILES

  print(f"Running protoc command: {' '.join(protoc_command)}")
  if subprocess.call(protoc_command) != 0:
    raise Exception("Failed to generate proto files")

  patch_grpc_import()


class BuildPyProto(build_py):

  def run(self) -> None:
    compile_protos()
    super().run()


class BuildExtEKM(build_ext):

  def run(self) -> None:
    super().run()


# C Extension module
ekm_module = Extension(
    "prompt_encryption_sdk.ekm._ekm",
    sources=["src/prompt_encryption_sdk/ekm/_ekm.c"],
    libraries=["ssl", "crypto"],
)

setup(
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    ext_modules=[ekm_module],
    cmdclass={
        "build_py": BuildPyProto,
        "build_ext": BuildExtEKM,
    },
    setup_requires=[
        "setuptools>=61.0",
        "wheel",
        "grpcio-tools",
    ],
    zip_safe=False,
    include_package_data=True,
)
