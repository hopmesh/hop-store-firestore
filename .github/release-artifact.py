#!/usr/bin/env python3
"""Create and verify immutable release artifact manifests."""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path, PurePosixPath


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SOURCE_RE = re.compile(r"^GitOrigin-RevId: ([0-9a-f]{40})$", re.MULTILINE)
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MANIFEST = "release-manifest.json"


class ArtifactError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ArtifactError(message)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def source_revision(repository):
    result = subprocess.run(
        ["git", "-C", str(repository), "show", "-s", "--format=%B", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode:
        raise ArtifactError(f"cannot read release commit: {result.stderr.strip()}")
    matches = SOURCE_RE.findall(result.stdout)
    require(len(matches) == 1, "release commit must have exactly one GitOrigin-RevId")
    return matches[0]


def context(args):
    repository = args.repository_name or os.environ.get("GITHUB_REPOSITORY", "")
    source_sha = args.source_sha or os.environ.get("GITHUB_SHA", "")
    source_ref = args.source_ref or os.environ.get("GITHUB_REF", "")
    run_id = args.run_id or os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = args.run_attempt or os.environ.get("GITHUB_RUN_ATTEMPT", "")
    require(REPOSITORY_RE.fullmatch(repository), "repository identity is invalid")
    require(SHA_RE.fullmatch(source_sha), "source SHA is not a full commit SHA")
    require(source_ref.startswith("refs/"), "source ref is invalid")
    require(run_id.isdigit() and int(run_id) > 0, "run ID is invalid")
    require(run_attempt.isdigit() and int(run_attempt) > 0, "run attempt is invalid")
    return repository, source_sha, source_ref, int(run_id), int(run_attempt)


def canonical_source(args):
    value = args.canonical_source_sha
    if value is None:
        value = source_revision(Path(args.repository).resolve())
    require(SHA_RE.fullmatch(value), "canonical source SHA is invalid")
    return value


def artifact_files(directory):
    files = []
    for path in sorted(directory.rglob("*")):
        if path == directory / MANIFEST:
            continue
        require(not path.is_symlink(), f"artifact is a symlink: {path}")
        if path.is_dir():
            continue
        require(path.is_file(), f"artifact is not a regular file: {path}")
        relative = path.relative_to(directory).as_posix()
        files.append(
            {
                "path": relative,
                "sha256": digest(path),
                "size": path.stat().st_size,
            }
        )
    return files


def create(args):
    directory = Path(args.directory).resolve()
    require(directory.is_dir(), "artifact directory is absent")
    manifest_path = directory / MANIFEST
    require(not manifest_path.exists(), "release manifest already exists")
    repository, source_sha, source_ref, run_id, run_attempt = context(args)
    manifest = {
        "canonical_source_sha": canonical_source(args),
        "files": artifact_files(directory),
        "repository": repository,
        "run_attempt": run_attempt,
        "run_id": run_id,
        "schema": 1,
        "source_ref": source_ref,
        "source_sha": source_sha,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"release manifest created: files={len(manifest['files'])} "
        f"source={source_sha} canonical={manifest['canonical_source_sha']}"
    )


def safe_relative(value):
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and all(
        part not in ("", ".", "..") for part in path.parts
    )


def load_manifest(path):
    require(path.is_file() and not path.is_symlink(), "release manifest is not a regular file")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ArtifactError(f"release manifest cannot be read: {error}") from error
    require(
        set(manifest)
        == {
            "canonical_source_sha",
            "files",
            "repository",
            "run_attempt",
            "run_id",
            "schema",
            "source_ref",
            "source_sha",
        },
        "release manifest fields are invalid",
    )
    require(manifest["schema"] == 1, "release manifest schema is unsupported")
    require(isinstance(manifest["files"], list), "release manifest files are invalid")
    return manifest


def verify(args):
    directory = Path(args.directory).resolve()
    require(directory.is_dir(), "artifact directory is absent")
    manifest = load_manifest(directory / MANIFEST)
    repository, source_sha, source_ref, run_id, run_attempt = context(args)
    require(manifest["repository"] == repository, "artifact repository does not match")
    require(manifest["source_sha"] == source_sha, "artifact source SHA does not match")
    require(manifest["source_ref"] == source_ref, "artifact source ref does not match")
    require(manifest["run_id"] == run_id, "artifact run ID does not match")
    require(manifest["run_attempt"] == run_attempt, "artifact run attempt does not match")
    require(
        manifest["canonical_source_sha"] == canonical_source(args),
        "artifact canonical source SHA does not match",
    )

    declared = {}
    for entry in manifest["files"]:
        require(
            isinstance(entry, dict) and set(entry) == {"path", "sha256", "size"},
            "artifact entry fields are invalid",
        )
        relative = entry["path"]
        require(isinstance(relative, str) and safe_relative(relative), "artifact path is unsafe")
        require(relative not in declared, f"duplicate artifact path: {relative}")
        require(
            isinstance(entry["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]),
            f"artifact digest is invalid: {relative}",
        )
        require(
            isinstance(entry["size"], int) and entry["size"] >= 0,
            f"artifact size is invalid: {relative}",
        )
        declared[relative] = entry

    actual = {entry["path"]: entry for entry in artifact_files(directory)}
    require(set(actual) == set(declared), "artifact inventory does not match manifest")
    for relative, entry in declared.items():
        require(actual[relative]["size"] == entry["size"], f"artifact size changed: {relative}")
        require(
            actual[relative]["sha256"] == entry["sha256"],
            f"artifact digest changed: {relative}",
        )
    print(
        f"release manifest verified: files={len(declared)} source={source_sha} "
        f"canonical={manifest['canonical_source_sha']}"
    )


def parser():
    result = argparse.ArgumentParser()
    result.add_argument("command", choices=("create", "verify"))
    result.add_argument("--directory", required=True)
    result.add_argument("--repository", default=".")
    result.add_argument("--repository-name")
    result.add_argument("--source-sha")
    result.add_argument("--source-ref")
    result.add_argument("--run-id")
    result.add_argument("--run-attempt")
    result.add_argument("--canonical-source-sha")
    return result


def main():
    args = parser().parse_args()
    try:
        create(args) if args.command == "create" else verify(args)
    except (ArtifactError, OSError, ValueError) as error:
        raise SystemExit(f"release artifact rejected: {error}") from error


if __name__ == "__main__":
    main()
