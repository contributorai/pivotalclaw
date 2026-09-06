import sys
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import audit_public_release


class HistoryAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ)
        for key in list(self.env):
            if key.startswith('GIT_') or key == 'EMAIL':
                del self.env[key]
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'contributorai')
        self.git('config', 'user.email', '130954494+contributorai@users.noreply.github.com')
        self.commit()

    def git(self, *args, env=None):
        return subprocess.check_output(['git', *args], cwd=self.root, env=env or self.env, stderr=subprocess.PIPE, text=True).strip()

    def commit(self, message='Safe change', **overrides):
        return self.git('commit', '--allow-empty', '-qm', message, env=dict(self.env, **overrides))

    def test_non_main_branch_requires_explicit_selection(self):
        self.git('checkout', '-qb', 'side')
        self.commit(GIT_AUTHOR_NAME='Mi' + 'sha')
        self.git('checkout', 'main')
        self.assertEqual([], audit_public_release.scan_history(self.root, refs=['main']))
        self.assertTrue(audit_public_release.scan_history(self.root, all_refs=True))

    def test_committer_and_message_are_audited_without_value_echo(self):
        self.commit('Mi' + 'sha public-audit: allow', GIT_COMMITTER_NAME='Mi' + 'sha')
        findings = audit_public_release.scan_history(self.root, refs=['HEAD'])
        self.assertTrue(any('committer' in f.path for f in findings))
        self.assertTrue(any('message' in f.path for f in findings))
        self.assertNotIn('Mi' + 'sha', repr(findings))

    def test_deleted_historical_text_is_audited(self):
        (self.root / 'old.txt').write_text('Mi' + 'sha\n')
        self.git('add', 'old.txt'); self.commit()
        self.git('rm', 'old.txt'); self.commit()
        self.assertEqual([], audit_public_release.scan_tree(self.root))
        self.assertTrue(any('blob/' in f.path for f in audit_public_release.scan_history(self.root, refs=['HEAD'])))

    def test_github_and_bot_identities_pass(self):
        self.commit('Safe update\n\nSigned-off-by: dependabot[bot] <support' + '@github.com>', GIT_AUTHOR_NAME='dependabot[bot]', GIT_AUTHOR_EMAIL='49699333+dependabot[bot]@users.noreply.github.com', GIT_COMMITTER_NAME='GitHub', GIT_COMMITTER_EMAIL='noreply@github.com')
        self.assertEqual([], audit_public_release.scan_history(self.root, refs=['HEAD']))

    def test_annotated_tags_and_nested_tags_are_audited(self):
        self.git('tag', '-a', 'inner', '-m', 'Mi' + 'sha', env=dict(self.env, GIT_COMMITTER_NAME='Mi' + 'sha'))
        self.git('tag', '-a', 'outer', 'inner', '-m', 'Safe tag')
        findings = audit_public_release.scan_history(self.root, refs=['refs/tags/outer'])
        self.assertTrue(any('/tag/' in f.path and f.rule == 'personal-name' for f in findings))

    def test_other_github_addresses_are_not_exempt(self):
        self.commit('Contact private-person' + '@github.com')
        self.assertTrue(audit_public_release.scan_history(self.root, refs=['HEAD']))

    def test_invalid_ref_fails_closed(self):
        with self.assertRaises(ValueError):
            audit_public_release.scan_history(self.root, refs=['--all'])

    def test_effective_identity_includes_environment_overrides(self):
        with patch.dict(os.environ, self.env, clear=True):
            self.assertEqual([], audit_public_release.scan_effective_identity(self.root))
        with patch.dict(os.environ, dict(self.env, GIT_COMMITTER_NAME='Wrong identity'), clear=True):
            self.assertTrue(audit_public_release.scan_effective_identity(self.root))


class PublicReleaseAuditTests(unittest.TestCase):
    def test_clean_release_tree_passes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("# Example project\n", encoding="utf-8")

            self.assertEqual([], audit_public_release.scan_tree(root))

    def test_personal_and_secret_material_is_reported_without_echoing_values(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "unsafe.txt").write_text(
                "Mi" + "sha owns this file\n"
                "/Users/private-user/project\n"  # public-audit: allow
                "owner@example.com\n"
                "postgres" + "ql://reader:" + "plain-text-password" + "@db.example.invalid/app\n",
                encoding="utf-8",
            )

            findings = audit_public_release.scan_tree(root)

        self.assertEqual(
            ["credential-url", "email-address", "macos-home-path", "personal-name"],
            sorted(finding.rule for finding in findings),
        )
        self.assertTrue(all(finding.path == "unsafe.txt" for finding in findings))
        self.assertNotIn("plain-text-password", repr(findings))

    def test_binary_files_are_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "asset.bin").write_bytes(b"\x00/Users/private-user\x00")

            self.assertEqual([], audit_public_release.scan_tree(root))


if __name__ == "__main__":
    unittest.main()
