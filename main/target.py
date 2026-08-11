"""Identify the repository being scanned.

Output is namespaced by the target so several applications can be analyzed without
collision. The local clone directory is a poor name for that — it is whatever the
person cloning happened to type, usually something like `repo` — so the identity comes
from the git remote instead:

    https://github.com/juice-shop/juice-shop.git   ->  juice-shop/juice-shop
    git@github.com:juice-shop/juice-shop.git       ->  juice-shop/juice-shop

giving `output/juice-shop/juice-shop/`. Two people who clone the same project to
different directory names then produce the same output path, and a report can say what
was actually analyzed rather than "repo".

Falls back to the directory name when the target is not a git checkout or has no
remote, so a plain source drop still works.

Standard library only.
"""

from __future__ import annotations

import pathlib
import re
import subprocess

# scheme://host/owner/name(.git) | user@host:owner/name(.git) | file paths
_REMOTE_RE = re.compile(
    r"""
    (?:                          # everything before the path
        [a-z][a-z0-9+.-]*://     #   scheme://
        (?:[^/@]+@)?[^/]+/       #   optional user@, then host/
      | [^/@]+@[^:/]+:           #   scp-style  user@host:
    )?
    (?P<path>.+?)                # owner/name, or just name
    (?:\.git)?                   # optional .git suffix
    /?$
    """,
    re.IGNORECASE | re.VERBOSE,
)

_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def parse_remote(url: str) -> str | None:
    """Extract `owner/name` from a git remote URL. None if it cannot be trusted."""
    url = (url or "").strip()
    if not url:
        return None

    match = _REMOTE_RE.match(url)
    if not match:
        return None

    segments = [s for s in match.group("path").split("/") if s]
    if not segments:
        return None

    # Keep the last two segments — owner and repository. A deeper path (self-hosted
    # GitLab subgroups, say) collapses to its final pair, which is still unique enough
    # to namespace by and short enough to read.
    segments = segments[-2:]

    # These become directory names, so refuse anything that could escape the tree.
    # `.` and `..` satisfy _SAFE_SEGMENT_RE (a dot is a legal character in a repo
    # name) but are traversal, so reject all-dot segments explicitly.
    if not all(_SAFE_SEGMENT_RE.match(s) and s.strip(".") for s in segments):
        return None

    return "/".join(segments)


def repo_slug(repo_path: pathlib.Path) -> str:
    """`owner/name` for the checkout at `repo_path`, else its directory name."""
    repo_path = pathlib.Path(repo_path)
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return repo_path.resolve().name

    if result.returncode == 0:
        slug = parse_remote(result.stdout)
        if slug:
            return slug
    return repo_path.resolve().name


def output_dir(repo_path: pathlib.Path, root: pathlib.Path = pathlib.Path("output")) -> pathlib.Path:
    """Where every stage reads and writes for this target."""
    return pathlib.Path(root).joinpath(*repo_slug(repo_path).split("/"))


def display_name(repo_path: pathlib.Path) -> str:
    """Just the repository name, for a report title."""
    return repo_slug(repo_path).split("/")[-1]
