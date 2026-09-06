#!/usr/bin/env python3
"""Fail a public release when tracked text exposes personal or secret material."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache"}
RULES = {
    "macos-home-path": re.compile(r"/Users/(?!example(?:/|\b))[^/\s]+/"),  # public-audit: allow
    "email-address": re.compile(
        r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@"
        r"(?!(?:example\.(?:com|org|net)|users\.noreply\.github\.com)\b)"
        r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    ),
    "credential-url": re.compile(
        r"\b(?:postgres(?:ql)?|mysql|redis|mongodb(?:\+srv)?)://"
        r"[^\s:/]+:[^\s/@]+@",
        re.IGNORECASE,
    ),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "openai-token": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
}
WORD_RE = re.compile(r"\b[A-Za-z][A-Za-z'-]{2,}\b")
PERSONAL_WORD_HASHES = {
    "bd576611e860bf15883a37b8d628c77e6dfb519757793a9d759fd861da067f77"
}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str


def _text_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        data = path.read_bytes()
        if b"\x00" in data:
            continue
        try:
            yield path, data.decode("utf-8")
        except UnicodeDecodeError:
            continue


def scan_text(text: str, location: str, *, allow_comments=False) -> list[Finding]:
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        if allow_comments and "public-audit: allow" in line:
            continue
        if any(hashlib.sha256(word.lower().encode()).hexdigest() in PERSONAL_WORD_HASHES
               for word in WORD_RE.findall(line)):
            findings.append(Finding(location, number, "personal-name"))
        for rule, pattern in RULES.items():
            candidate = line
            if rule == "email-address":
                # GitHub's web committer is a specific known identity, not a
                # blanket exemption for every address on github.com.
                candidate = re.sub(r"(?<![A-Za-z0-9._%+-])noreply@github\.com(?![A-Za-z0-9.-])", "", line)
                if line == "Signed-off-by: dependabot[bot] <support" + "@github.com>":
                    candidate = ""
            if pattern.search(candidate):
                findings.append(Finding(location, number, rule))
    return findings


def scan_tree(root: Path) -> list[Finding]:
    root = Path(root).resolve()
    return [finding for path, text in _text_files(root)
            for finding in scan_text(text, path.relative_to(root).as_posix(), allow_comments=True)]


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, check=False)
    if result.returncode:
        # Git errors can echo private paths, refs, or configuration values.
        raise ValueError("Git audit could not resolve or read the requested repository data")
    return result.stdout


def _selected_refs(root: Path, refs=None, all_refs=False) -> list[str]:
    if refs and all_refs:
        raise ValueError("Choose explicit refs or all refs, not both")
    if _git(root, "rev-parse", "--is-shallow-repository").strip() == b"true":
        raise ValueError("History audit requires a complete, non-shallow checkout")
    if all_refs:
        selected = _git(root, "for-each-ref", "--format=%(refname)",
                        "refs/heads/", "refs/remotes/", "refs/tags/").decode().splitlines()
        if not selected:
            raise ValueError("No branches or tags available to audit")
    else:
        selected = refs or ["HEAD"]
    return selected


def _commits(root: Path, refs) -> list[str]:
    resolved = [_git(root, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").decode().strip()
                for ref in refs]
    return _git(root, "rev-list", *resolved, "--").decode().splitlines()


def scan_history(root: Path, refs=None, *, all_refs=False, include_blobs=True) -> list[Finding]:
    """Audit reachable commits and unique historical UTF-8 blobs.

    No network access: callers must fetch advertised refs first. Hidden refs,
    forks, caches, binaries and bypass-marked source lines require other review.
    Metadata never honors source-code bypass comments. Locations use object IDs
    rather than potentially sensitive historical filenames.
    """
    findings = []
    seen = set()
    selected = _selected_refs(root, refs, all_refs)
    seen_tags = set()
    for ref in selected:
        oid = _git(root, "rev-parse", "--verify", "--end-of-options", ref).decode().strip()
        findings.extend(scan_text(ref, f".git/ref/{oid}"))
        while _git(root, "cat-file", "-t", oid).strip() == b"tag" and oid not in seen_tags:
            seen_tags.add(oid)
            tag = _git(root, "cat-file", "tag", oid).decode("utf-8", "replace")
            findings.extend(scan_text(tag, f".git/tag/{oid}"))
            oid = tag.splitlines()[0].removeprefix("object ")
    for commit in _commits(root, selected):
        metadata = _git(root, "show", "-s", "--format=%an <%ae>%x00%cn <%ce>%x00%B", commit).decode("utf-8", "replace")
        for field, value in zip(("author", "committer", "message"), metadata.split("\x00", 2)):
            findings.extend(scan_text(value, f".git/commit/{commit}/{field}"))
        if not include_blobs:
            continue
        for entry in _git(root, "ls-tree", "-rz", commit).split(b"\x00"):
            if not entry:
                continue
            info, name = entry.split(b"\t", 1)
            mode, kind, oid = info.split()
            blob = oid.decode("ascii")
            findings.extend(scan_text(name.decode("utf-8", "replace"), f".git/tree/{commit}/{blob}"))
            if kind != b"blob" or oid in seen:
                continue
            seen.add(oid)
            data = _git(root, "cat-file", "blob", blob)
            if b"\x00" in data:
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            findings.extend(scan_text(text, f".git/blob/{blob}", allow_comments=True))
    return findings


def scan_commit_identities(root: Path) -> list[Finding]:
    """Compatibility entry point; now includes committer and commit messages."""
    return scan_history(root, include_blobs=False)


def scan_effective_identity(root: Path) -> list[Finding]:
    expected = "contributorai <130954494+contributorai@users.noreply.github.com>"
    findings = []
    for role in ("AUTHOR", "COMMITTER"):
        value = _git(root, "var", f"GIT_{role}_IDENT").decode("utf-8", "replace").strip()
        identity = value.rsplit(" ", 2)[0]
        if identity != expected:
            findings.append(Finding(f".git/effective-{role.lower()}", 1, "unapproved-public-identity"))
    return findings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument(
        "--history", action="store_true", help="audit reachable commit metadata and historical text (HEAD by default)"
    )
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--ref", action="append", dest="refs", help="history root; repeat for each outgoing ref")
    selection.add_argument("--all-refs", action="store_true", help="audit all locally fetched branches and tags")
    parser.add_argument("--check-identity", action="store_true", help="require approved effective public author and committer")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    findings = scan_tree(root)
    try:
        if args.history or args.refs or args.all_refs:
            findings.extend(scan_history(root, args.refs, all_refs=args.all_refs))
        if args.check_identity:
            findings.extend(scan_effective_identity(root))
    except ValueError as error:
        print(f"Public-release audit failed: {error}.")
        return 2
    if findings:
        for finding in findings:
            print(f"{finding.path}:{finding.line}: {finding.rule}")
        print(f"Public-release audit failed with {len(findings)} finding(s).")
        return 1
    print("Public-release audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
