#!/usr/bin/env python3
"""Create crates.io metadata and publish an already verified .crate archive."""

import argparse
import json
import os
import struct
import subprocess
import tarfile
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath


PUBLISH_FIELDS = {
    "authors",
    "badges",
    "categories",
    "deps",
    "description",
    "documentation",
    "features",
    "homepage",
    "keywords",
    "license",
    "license_file",
    "links",
    "name",
    "readme",
    "readme_file",
    "repository",
    "rust_version",
    "vers",
}


class CrateError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise CrateError(message)


def relative_file(value, root, label):
    if value is None:
        return None, None
    path = Path(value).resolve()
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise CrateError(f"{label} is outside the package root") from error
    require(path.is_file(), f"{label} is absent")
    return path.read_text(encoding="utf-8"), relative


def dependency_metadata(dependency):
    require(dependency.get("source") is not None, f"path dependency cannot be published: {dependency.get('name')}")
    return {
        "default_features": dependency["uses_default_features"],
        "explicit_name_in_toml": dependency.get("rename"),
        "features": dependency["features"],
        "kind": dependency.get("kind") or "normal",
        "name": dependency["name"],
        "optional": dependency["optional"],
        "registry": dependency.get("registry"),
        "target": dependency.get("target"),
        "version_req": dependency["req"],
    }


def package_metadata(package):
    root = Path(package["manifest_path"]).resolve().parent
    readme, readme_file = relative_file(package.get("readme"), root, "README")
    _, license_file = relative_file(package.get("license_file"), root, "license file")
    metadata = {
        "authors": package.get("authors") or [],
        "badges": {},
        "categories": package.get("categories") or [],
        "deps": [dependency_metadata(item) for item in package.get("dependencies", [])],
        "description": package.get("description"),
        "documentation": package.get("documentation"),
        "features": package.get("features") or {},
        "homepage": package.get("homepage"),
        "keywords": package.get("keywords") or [],
        "license": package.get("license"),
        "license_file": license_file,
        "links": package.get("links"),
        "name": package["name"],
        "readme": readme,
        "readme_file": readme_file,
        "repository": package.get("repository"),
        "rust_version": package.get("rust_version"),
        "vers": package["version"],
    }
    require(set(metadata) == PUBLISH_FIELDS, "crate publication metadata fields drifted")
    require(metadata["description"], "crate description is required")
    require(metadata["license"] or metadata["license_file"], "crate license metadata is required")
    return metadata


def validate_crate(path, metadata):
    path = Path(path).resolve()
    require(path.is_file() and path.suffix == ".crate", "crate archive is absent or has a wrong extension")
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        require(members, "crate archive is empty")
        roots = set()
        for member in members:
            pure = PurePosixPath(member.name)
            require(not pure.is_absolute(), "crate archive contains an absolute path")
            require(all(part not in ("", ".", "..") for part in pure.parts), "crate archive contains an unsafe path")
            require(member.isfile() or member.isdir(), "crate archive contains a non-regular entry")
            roots.add(pure.parts[0])
        expected_root = f"{metadata['name']}-{metadata['vers']}"
        require(roots == {expected_root}, "crate archive root differs from publication metadata")
        manifest_name = expected_root + "/Cargo.toml"
        try:
            manifest = archive.extractfile(manifest_name)
        except KeyError as error:
            raise CrateError("crate archive omits Cargo.toml") from error
        require(manifest is not None, "crate Cargo.toml cannot be read")
        try:
            import tomllib

            package = tomllib.loads(manifest.read().decode("utf-8"))["package"]
        except (KeyError, UnicodeDecodeError, ValueError) as error:
            raise CrateError("crate Cargo.toml is invalid") from error
        require(package.get("name") == metadata["name"], "crate name differs from publication metadata")
        require(package.get("version") == metadata["vers"], "crate version differs from publication metadata")
    return path.read_bytes()


def create_metadata(args):
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--no-deps",
        "--format-version",
        "1",
        "--manifest-path",
        args.manifest,
    ]
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        raise CrateError("cargo metadata failed: " + result.stderr.strip())
    payload = json.loads(result.stdout)
    packages = payload.get("packages", [])
    require(len(packages) == 1, f"expected one publish package, found {len(packages)}")
    metadata = package_metadata(packages[0])
    validate_crate(args.crate, metadata)
    output = Path(args.output)
    require(not output.exists(), "crate publication metadata already exists")
    output.write_text(json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"crate publication metadata created: {metadata['name']} {metadata['vers']}")


def publish(args):
    metadata_path = Path(args.metadata)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    require(isinstance(metadata, dict) and set(metadata) == PUBLISH_FIELDS, "crate publication metadata is invalid")
    crate = validate_crate(args.crate, metadata)
    encoded = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body = struct.pack("<I", len(encoded)) + encoded + struct.pack("<I", len(crate)) + crate
    token = os.environ.get("CARGO_REGISTRY_TOKEN", "")
    require(token and "\n" not in token and "\r" not in token, "crates.io token is absent or invalid")
    request = urllib.request.Request(
        "https://crates.io/api/v1/crates/new",
        data=body,
        method="PUT",
        headers={
            "Accept": "application/json",
            "Authorization": token,
            "Content-Type": "application/octet-stream",
            "User-Agent": "hop-release/1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            response_body = response.read()
            require(response.status in range(200, 300), f"crates.io publish failed: HTTP {response.status}")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        raise CrateError(f"crates.io publish failed: HTTP {error.code}: {detail}") from error
    result = json.loads(response_body or b"{}")
    errors = result.get("errors", [])
    require(not errors, f"crates.io rejected publication: {errors}")
    print(f"published verified crate: {metadata['name']} {metadata['vers']}")


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    metadata = subparsers.add_parser("metadata")
    metadata.add_argument("--manifest", default="Cargo.toml")
    metadata.add_argument("--crate", required=True)
    metadata.add_argument("--output", required=True)
    upload = subparsers.add_parser("publish")
    upload.add_argument("--crate", required=True)
    upload.add_argument("--metadata", required=True)
    args = parser.parse_args()
    try:
        create_metadata(args) if args.command == "metadata" else publish(args)
    except (CrateError, OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as error:
        raise SystemExit(f"crate publication rejected: {error}") from error


if __name__ == "__main__":
    main()
