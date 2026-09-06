import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_public_release


class BuildPublicReleaseTests(unittest.TestCase):
    def test_release_manifest_keeps_internal_roadmap_private(self):
        manifest = (REPO_ROOT / "PUBLIC_RELEASE_FILES.txt").read_text(encoding="utf-8")

        self.assertNotIn("docs/roadmap.md", manifest.splitlines())

    def test_manifest_globs_copy_only_selected_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "source"
            destination = Path(td) / "release"
            (root / "app" / "tests").mkdir(parents=True)
            (root / "README.md").write_text("read me", encoding="utf-8")
            (root / "private.txt").write_text("private", encoding="utf-8")
            (root / "app" / "main.py").write_text("print('ok')", encoding="utf-8")
            (root / "app" / "tests" / "test_main.py").write_text("pass", encoding="utf-8")
            manifest = root / "PUBLIC_RELEASE_FILES.txt"
            manifest.write_text("README.md\napp/*.py\napp/tests/*.py\n", encoding="utf-8")

            copied = build_public_release.build(root, manifest, destination)

            self.assertEqual(
                ["README.md", "app/main.py", "app/tests/test_main.py"], copied
            )
            self.assertFalse((destination / "private.txt").exists())

    def test_symlink_to_private_file_inside_root_is_rejected(self):
        """A symlink sitting in an allowlisted directory must not smuggle private
        content into the candidate. The escape guard only catches targets outside
        the root, so an in-root symlink such as tree_viewer/x.js -> ../icebox.md
        would otherwise be copied with its private contents."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "source"
            (root / "app").mkdir(parents=True)
            (root / "private.txt").write_text("PRIVATE", encoding="utf-8")
            (root / "app" / "real.py").write_text("ok", encoding="utf-8")
            (root / "app" / "leak.py").symlink_to(Path("..") / "private.txt")
            manifest = root / "PUBLIC_RELEASE_FILES.txt"
            manifest.write_text("app/*.py\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                build_public_release.build(root, manifest, Path(td) / "release")

    def test_symlinked_allowlisted_file_does_not_leak_content(self):
        """Even if the build is retried, no private bytes may reach the output."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "source"
            (root / "app").mkdir(parents=True)
            (root / "private.txt").write_text("PRIVATE", encoding="utf-8")
            (root / "app" / "real.py").write_text("ok", encoding="utf-8")
            (root / "app" / "leak.py").symlink_to(Path("..") / "private.txt")
            manifest = root / "PUBLIC_RELEASE_FILES.txt"
            manifest.write_text("app/*.py\n", encoding="utf-8")
            destination = Path(td) / "release"

            try:
                build_public_release.build(root, manifest, destination)
            except ValueError:
                pass
            leaked = destination / "app" / "leak.py"
            self.assertFalse(leaked.exists(), "symlinked private file reached the candidate")

    def test_symlinked_parent_directory_is_rejected(self):
        """A symlinked directory in the path must be refused too, not just a
        symlinked leaf file."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "source"
            (root / "secretdir").mkdir(parents=True)
            (root / "secretdir" / "x.py").write_text("PRIVATE", encoding="utf-8")
            (root / "app").symlink_to(root / "secretdir")
            manifest = root / "PUBLIC_RELEASE_FILES.txt"
            manifest.write_text("app/*.py\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                build_public_release.build(root, manifest, Path(td) / "release")

    def test_manifest_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "source"
            root.mkdir()
            manifest = root / "PUBLIC_RELEASE_FILES.txt"
            manifest.write_text("../secret.txt\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                build_public_release.build(root, manifest, Path(td) / "release")


if __name__ == "__main__":
    unittest.main()
