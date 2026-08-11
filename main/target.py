"""Identify the repository being scanned.

Both the clone and the output are named after the repository, so a target lives at a
predictable pair of paths:

    https://github.com/juice-shop/juice-shop.git  ->  repo/juice-shop
                                                      output/juice-shop

The name comes from the git remote rather than the local directory, so two people who
cloned to differently-named directories still produce the same output path, and a
report can say what was actually analyzed rather than "repo". Falls back to the
directory name when the target is not a git checkout or has no remote, so a plain
source drop still works.

`repo_slug()` keeps the full `owner/name` for provenance — it is what a report or a log
line should say — while paths use `repo_name()`, the last segment only.

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


def is_url(target: str) -> bool:
    """True for something to clone rather than a path on disk."""
    text = str(target)
    return bool(re.match(r"^[a-z][a-z0-9+.-]*://", text, re.I)) or bool(re.match(r"^[^/\\]+@[^:/]+:", text))


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


def repo_name(target: pathlib.Path | str) -> str:
    """The repository name alone — the segment both `repo/` and `output/` are keyed by."""
    if isinstance(target, str) and is_url(target):
        slug = parse_remote(target)
        if not slug:
            raise ValueError(f"cannot derive a repository name from {target!r}")
        return slug.split("/")[-1]
    return repo_slug(pathlib.Path(target)).split("/")[-1]


def output_dir(target: pathlib.Path | str, root: pathlib.Path = pathlib.Path("output")) -> pathlib.Path:
    """Where every stage reads and writes for this target."""
    return pathlib.Path(root) / repo_name(target)


def clone_dir(target: pathlib.Path | str, root: pathlib.Path = pathlib.Path("repo")) -> pathlib.Path:
    """Where a cloned target lives, mirroring the output naming."""
    return pathlib.Path(root) / repo_name(target)


def ensure_clone(url: str, dest: pathlib.Path) -> pathlib.Path:
    """Shallow-clone `url` to `dest` if it is not already there. Returns `dest`."""
    if (dest / ".git").is_dir():
        return dest
    if dest.exists() and any(dest.iterdir()):
        raise SystemExit(f"{dest} exists and is not a git checkout — move it or pass an explicit --repo")

    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"cloning {url} -> {dest}", flush=True)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--single-branch", url, str(dest)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"clone failed:\n{result.stderr.strip()}")
    return dest


def resolve_target(target: pathlib.Path | str, clone_root: pathlib.Path = pathlib.Path("repo")) -> pathlib.Path:
    """Accept a path or a URL; return a local checkout, cloning it if needed."""
    if isinstance(target, str) and is_url(target):
        return ensure_clone(target, clone_dir(target, clone_root))
    return pathlib.Path(target)
