# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test ensuring all public Python SDK symbols are documented in python.md."""

import ast
import os
import unittest

# Directory holding this test, and the repository root relative to it.
# This file lives at <repo root>/g3doc/user_guide/sdk/, so the root is four
# levels up. Paths are resolved this way, rather than from a hardcoded
# repository prefix, so the test works from any checkout layout.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_SCRIPT_DIR, *([os.pardir] * 4)))


def find_file(rel_path: str) -> str:
  """Locates a required file from filesystem or test runfiles.

  Args:
    rel_path: Path of the file relative to the repository root.

  Returns:
    A path to the file that can be opened.

  Raises:
    FileNotFoundError: If the file cannot be located.
  """
  native_rel_path = rel_path.replace("/", os.sep)
  candidates = [
      rel_path,
      os.path.join(_REPO_ROOT, native_rel_path),
      os.path.join(_SCRIPT_DIR, os.path.basename(rel_path)),
  ]
  for candidate in candidates:
    if os.path.isfile(candidate):
      return candidate

  # Under Bazel the file lives beneath a runfiles directory, prefixed by a
  # workspace name that differs between checkouts, so search for any path
  # ending with the repository-relative path.
  runfiles_dirs = [
      os.environ.get("TEST_SRCDIR"),
      os.environ.get("RUNFILES_DIR"),
      os.environ.get("PYTHON_RUNFILES"),
  ]
  fname = os.path.basename(rel_path)
  for rdir in runfiles_dirs:
    if not rdir or not os.path.isdir(rdir):
      continue
    for root, _, files in os.walk(rdir):
      if fname in files:
        candidate = os.path.join(root, fname)
        if candidate.endswith(native_rel_path):
          return candidate

  raise FileNotFoundError(f"Could not locate file: {rel_path}")


class PythonDocsApiTest(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    sandbox_py_path = find_file("sandboxexec/sandbox/python/gvisor/sandbox.py")
    python_md_path = find_file("g3doc/user_guide/sdk/python.md")

    with open(sandbox_py_path, "r", encoding="utf-8") as f:
      cls.source_code = f.read()
    cls.tree = ast.parse(cls.source_code, filename="sandbox.py")

    with open(python_md_path, "r", encoding="utf-8") as f:
      cls.doc_content = f.read()

  def test_public_classes_documented(self):
    """Verifies all top-level public classes are documented."""
    public_classes = [
        node.name
        for node in self.tree.body
        if isinstance(node, ast.ClassDef) and not node.name.startswith("_")
    ]
    self.assertTrue(public_classes)

    missing = [
        cls_name
        for cls_name in public_classes
        if cls_name not in self.doc_content
    ]
    self.assertEqual(
        missing,
        [],
        f"Public classes missing from python.md: {missing}",
    )

  def test_public_methods_documented(self):
    """Verifies all public methods and properties are documented."""
    missing = []
    for node in self.tree.body:
      if not isinstance(node, ast.ClassDef) or node.name.startswith("_"):
        continue
      cls_name = node.name
      for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
          if item.name.startswith("_") and item.name != "__init__":
            continue
          method_name = item.name
          # Check that the method name appears in documentation
          if method_name not in self.doc_content:
            missing.append(f"{cls_name}.{method_name}")

    self.assertEqual(
        missing,
        [],
        f"Public methods/properties missing from python.md: {missing}",
    )

  def test_sandbox_init_parameters_documented(self):
    """Verifies key Sandbox.__init__ parameters are documented."""
    sandbox_cls = next(
        node
        for node in self.tree.body
        if isinstance(node, ast.ClassDef) and node.name == "Sandbox"
    )
    init_func = next(
        item
        for item in sandbox_cls.body
        if isinstance(item, ast.FunctionDef) and item.name == "__init__"
    )
    param_names = [arg.arg for arg in init_func.args.args if arg.arg != "self"]

    missing = [
        param for param in param_names if f"`{param}`" not in self.doc_content
    ]
    self.assertEqual(
        missing,
        [],
        f"Sandbox.__init__ parameters missing from python.md: {missing}",
    )


if __name__ == "__main__":
  unittest.main()
