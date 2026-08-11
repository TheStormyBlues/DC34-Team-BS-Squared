"""Tests for target identification.

The slug becomes a filesystem path, so a remote URL is untrusted input here — a
traversal segment reaching `output_dir()` would write outside the output tree.
"""

from __future__ import annotations

import pathlib

import pytest

from main.target import display_name, output_dir, parse_remote, repo_slug


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/juice-shop/juice-shop.git", "juice-shop/juice-shop"),
        ("https://github.com/juice-shop/juice-shop", "juice-shop/juice-shop"),
        ("https://github.com/juice-shop/juice-shop/", "juice-shop/juice-shop"),
        ("git@github.com:juice-shop/juice-shop.git", "juice-shop/juice-shop"),
        ("ssh://git@github.com/OWASP/threat-dragon.git", "OWASP/threat-dragon"),
        ("https://user@gitlab.com/group/sub/project.git", "sub/project"),
        ("  https://github.com/a/b.git  ", "a/b"),
    ],
)
def test_parse_remote(url, expected):
    assert parse_remote(url) == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/foo/bar.js.git", "foo/bar.js"),
        ("https://github.com/a.b/c.d", "a.b/c.d"),
    ],
)
def test_dots_are_legal_inside_a_name(url, expected):
    """`.` is a valid character in a repository name — only all-dot segments are traversal."""
    assert parse_remote(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "https://github.com/",
        "https://github.com/../../etc",
        "https://github.com/a/..",
        "https://github.com/./x",
        "git@host:../escape.git",
        "https://github.com/a/b c",
        "https://github.com/a/b;rm -rf",
    ],
)
def test_unsafe_or_empty_remotes_are_rejected(url):
    assert parse_remote(url) is None


def test_output_dir_nests_owner_and_name(tmp_path, monkeypatch):
    monkeypatch.setattr("main.target.repo_slug", lambda p: "juice-shop/juice-shop")
    assert output_dir(tmp_path) == pathlib.Path("output/juice-shop/juice-shop")


def test_output_dir_stays_inside_the_root(tmp_path, monkeypatch):
    """Whatever the slug, the result must not escape the output root."""
    monkeypatch.setattr("main.target.repo_slug", lambda p: "owner/name")
    resolved = (pathlib.Path.cwd() / output_dir(tmp_path)).resolve()
    assert resolved.is_relative_to((pathlib.Path.cwd() / "output").resolve())


def test_non_git_directory_falls_back_to_its_name(tmp_path):
    plain = tmp_path / "some-source-drop"
    plain.mkdir()
    assert repo_slug(plain) == "some-source-drop"


def test_display_name_is_the_repository_only(monkeypatch, tmp_path):
    monkeypatch.setattr("main.target.repo_slug", lambda p: "juice-shop/juice-shop")
    assert display_name(tmp_path) == "juice-shop"
