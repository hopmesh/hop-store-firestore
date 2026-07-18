#!/usr/bin/env python3
"""Generate exact Copybara exports and validate packages outside the monorepo."""

import argparse
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath


GO_CGO_MONOREPO = """#cgo CFLAGS: -I${SRCDIR}/..
#cgo LDFLAGS: -L${SRCDIR}/../../target/debug -lhop -Wl,-rpath,${SRCDIR}/../../target/debug -Wl,-rpath,${SRCDIR}/../../target/debug/deps
"""
GO_CGO_EXPORT = """#cgo pkg-config: hop
"""
ELIXIR_HOP_PATH_DEP = 'hop = { path = "../../../../core/hop" }'
ELIXIR_HOP_VENDOR_DEP = 'hop = { workspace = true }'
RUST_MIRRORS = {
    "hop-core",
    "libhop",
    "hop-wasm",
    "hop-store-sqlite",
    "hop-store-firestore",
    "hop-relayd",
    "hop-endpoint",
    "hop-gateway",
}
NATIVE_COMPONENTS = {"hop-sdk-go", "hop-sdk-apple", "hop-sdk-android", "hop-embedded"}
PACKAGE_COMPONENTS = ("hop-sdk-go", "hop-sdk-elixir", "hop-sdk-apple", "hop-sdk-android", "hop-embedded")
ANDROID_GRADLE_VERSION = "9.5.1"
ANDROID_AGP_VERSION = "9.2.1"
ANDROID_KOTLIN_VERSION = "2.4.0"
ANDROID_COMPILE_SDK = 36
ANDROID_ABIS = {
    "arm64-v8a": 183,
    "armeabi-v7a": 40,
    "x86": 3,
    "x86_64": 62,
}
GO_MODULE_METADATA_DIRECTORIES = {
    ".build",
    ".bzr",
    ".git",
    ".gradle",
    ".hg",
    ".idea",
    ".svn",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
}
GO_MODULE_METADATA_PREFIXES = {("native", "lib")}
ELIXIR_VENDOR = {
    "core/hop-core": "native/vendor/hop-core",
    "core/hop-endpoint": "native/vendor/hop-endpoint-core",
    "core/stores/hop-store-sqlite": "native/vendor/hop-store-sqlite",
    "core/hop": "native/vendor/libhop",
}
SHARED_EXPORTS = {
    "tools/release-provenance.py": ".github/release-provenance.py",
    "tools/release-artifact.py": ".github/release-artifact.py",
    "tools/copybara/components.json": ".github/components.json",
    "tools/package-export-smoke.py": ".github/package-export-smoke.py",
}
NATIVE_EXPORTS = {
    "tools/native-artifacts.py": "native/native-artifacts.py",
    "tools/native-artifacts.schema.json": "native/native-artifacts.schema.json",
    "tools/native-artifacts-public.pem": "native/native-artifacts-public.pem",
}
RUST_EXPORTS = {"tools/crates-publish.py": ".github/crates-publish.py"}


class ExportError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ExportError(message)


def run(command, cwd, env=None, capture=False):
    print("+", " ".join(str(part) for part in command), f"(cwd={cwd})", flush=True)
    result = subprocess.run(
        [str(part) for part in command],
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if result.returncode:
        detail = ""
        if capture:
            detail = "\n" + (result.stdout or "") + (result.stderr or "")
        raise ExportError(f"command failed ({result.returncode}): {' '.join(str(part) for part in command)}{detail}")
    return (result.stdout or "").strip() if capture else ""


def load_components(root):
    path = Path(root) / "tools/copybara/components.json"
    try:
        components = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ExportError(f"component map cannot be loaded: {error}") from error
    require(isinstance(components, dict) and components, "component map is empty")
    return components


def source_mode(path):
    if path.is_symlink():
        return "120000"
    return "100755" if path.stat().st_mode & stat.S_IXUSR else "100644"


def source_value(path):
    if path.is_symlink():
        return source_mode(path), os.readlink(path).encode("utf-8")
    return source_mode(path), path.read_bytes()


def repository_files(root):
    root = Path(root).resolve()
    in_worktree = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ).stdout.strip() == "true"
    if in_worktree:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            check=True,
            stdout=subprocess.PIPE,
        )
        return {item.decode("utf-8") for item in result.stdout.split(b"\0") if item}
    return {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file() or path.is_symlink()}


def add_file(tree, source_root, source, destination):
    source_path = Path(source_root) / source
    require(source_path.is_file() or source_path.is_symlink(), f"export source is missing: {source}")
    require(destination not in tree, f"export destination is duplicated: {destination}")
    tree[destination] = source_value(source_path)


def add_tree(tree, source_root, available, source_prefix, destination_prefix, exclude=()):
    source_prefix = source_prefix.rstrip("/")
    excluded = set(exclude)
    matches = sorted(path for path in available if path.startswith(source_prefix + "/"))
    require(matches, f"export source tree is empty: {source_prefix}")
    for source in matches:
        relative = source[len(source_prefix) + 1 :]
        if relative in excluded:
            continue
        destination = "/".join(part for part in (destination_prefix.rstrip("/"), relative) if part)
        add_file(tree, source_root, source, destination)


def replace_text(tree, path, before, after, label):
    require(path in tree, f"{label} file is missing: {path}")
    mode, raw = tree[path]
    text = raw.decode("utf-8")
    require(text.count(before) == 1, f"{label} anchor count is {text.count(before)}, expected 1")
    tree[path] = mode, text.replace(before, after, 1).encode("utf-8")


def workspace_preamble(copybara_config):
    text = Path(copybara_config).read_text(encoding="utf-8")
    match = re.search(r'WORKSPACE_PREAMBLE = """(.*?)"""', text, re.DOTALL)
    require(match is not None, "Copybara workspace preamble is missing")
    return match.group(1)


def expected_export_tree(source_root, component, components=None, available=None):
    source_root = Path(source_root).resolve()
    components = components or load_components(source_root)
    require(component in components, f"component is not allowlisted: {component}")
    entry = components[component]
    prefix = entry["prefix"]
    available = available or repository_files(source_root)
    tree = {}
    subtree_excludes = ("CLAUDE.md",)
    if component == "hop-sdk-elixir":
        subtree_excludes += ("native/hop_endpoint/Cargo.lock",)
    add_tree(tree, source_root, available, prefix, "", exclude=subtree_excludes)
    for source, destination in SHARED_EXPORTS.items():
        add_file(tree, source_root, source, destination)
    if component in NATIVE_COMPONENTS:
        for source, destination in NATIVE_EXPORTS.items():
            add_file(tree, source_root, source, destination)
    if component in RUST_MIRRORS:
        for source, destination in RUST_EXPORTS.items():
            add_file(tree, source_root, source, destination)
    if component == "hop-sdk-go":
        add_file(tree, source_root, "sdk/hop.h", "hop.h")
    if component == "hop-sdk-android":
        add_file(tree, source_root, "sdk/hop.h", "include/hop.h")
    if component == "hop-sdk-elixir":
        add_file(tree, source_root, "tools/copybara/elixir-native-Cargo.toml", "native/Cargo.toml")
        add_file(tree, source_root, "tools/copybara/elixir-native-Cargo.lock", "native/Cargo.lock")
        for source, destination in ELIXIR_VENDOR.items():
            add_tree(tree, source_root, available, source, destination, exclude=("CLAUDE.md",))
        replace_text(
            tree,
            "native/hop_endpoint/Cargo.toml",
            ELIXIR_HOP_PATH_DEP + "\n\n[workspace]\n",
            ELIXIR_HOP_VENDOR_DEP + "\n",
            "Elixir vendored workspace dependency",
        )
    if component == "hop-sdk-go":
        replace_text(tree, "hop.go", GO_CGO_MONOREPO, GO_CGO_EXPORT, "Go standalone cgo paths")
    rename = entry.get("rename")
    if rename:
        before = f'[package]\nname = "{rename[0]}"\n'
        after = f'[package]\nname = "{rename[1]}"\n'
        replace_text(tree, "Cargo.toml", before, after, f"{component} package rename")
    if component in RUST_MIRRORS:
        preamble = workspace_preamble(source_root / "tools/copybara/copy.bara.sky")
        replace_text(tree, "Cargo.toml", "[package]\n", preamble, f"{component} workspace injection")
    return tree


def write_export(tree, destination):
    destination = Path(destination)
    require(not destination.exists(), f"export destination already exists: {destination}")
    require(destination.parent.is_dir(), f"export destination parent is missing: {destination.parent}")
    destination.mkdir()
    for relative in sorted(tree):
        mode, payload = tree[relative]
        path = destination.joinpath(*PurePosixPath(relative).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        if mode == "120000":
            path.symlink_to(payload.decode("utf-8"))
        else:
            path.write_bytes(payload)
            path.chmod(0o755 if mode == "100755" else 0o644)


def export_component(root, component, destination):
    tree = expected_export_tree(root, component)
    write_export(tree, destination)
    return tree


def check_copybara_contract(root, components):
    config = (Path(root) / "tools/copybara/copy.bara.sky").read_text(encoding="utf-8")
    configured = dict(re.findall(r'^\s*\("([^"]+)", "([^"]+)"\),$', config, re.MULTILINE))
    mapped = {entry["prefix"]: name for name, entry in components.items()}
    require(configured == mapped, "Copybara component tuples differ from components.json")
    required = (
        'core.move(PROVENANCE_HELPER, ".github/release-provenance.py")',
        'core.move(CRATES_PUBLISH_HELPER, ".github/crates-publish.py")',
        'core.move(EXPORT_SMOKE, ".github/package-export-smoke.py")',
        'core.move(NATIVE_HELPER, "native/native-artifacts.py")',
        'core.move(HOP_HEADER, "include/hop.h")',
        "_go_export_paths()",
        "_elixir_vendor_export()",
    )
    for marker in required:
        require(marker in config, f"Copybara transformation marker is missing: {marker}")


def static_check(root, output_root, selected):
    root = Path(root).resolve()
    output_root = Path(output_root).resolve()
    require(output_root.is_dir(), f"output root is missing: {output_root}")
    require(not any(output_root.iterdir()), f"output root is not empty: {output_root}")
    components = load_components(root)
    check_copybara_contract(root, components)
    for component in selected:
        destination = output_root / component
        tree = export_component(root, component, destination)
        require("CLAUDE.md" not in tree, f"{component} leaked its monorepo CLAUDE.md")
        require(".github/release-provenance.py" in tree, f"{component} lacks release provenance")
        require(".github/package-export-smoke.py" in tree, f"{component} lacks export contract helper")
        if component in RUST_MIRRORS and ".github/workflows/release.yml" in tree:
            require("Cargo.lock" in tree, f"{component} release has no standalone Cargo lock")
            run(
                ["cargo", "metadata", "--locked", "--format-version", "1"],
                destination,
                capture=True,
            )
        for parent_marker in ("Cargo.lock", "DESIGN.md", "sdk/hop.h", "tools/CLAUDE.md"):
            if parent_marker not in tree:
                require(not (destination / parent_marker).exists(), f"{component} leaked monorepo parent file {parent_marker}")
    print(f"exact Copybara exports generated: {', '.join(selected)}")


def native_paths(bundle):
    bundle = Path(bundle).resolve()
    return (
        bundle / "native-artifacts.json",
        bundle / "native-artifacts.json.sig",
        bundle,
    )


def extract_target(export, bundle, target, destination):
    manifest, signature, directory = native_paths(bundle)
    run(
        [
            "python3",
            export / "native/native-artifacts.py",
            "extract",
            "--manifest",
            manifest,
            "--signature",
            signature,
            "--public-key",
            export / "native/native-artifacts-public.pem",
            "--directory",
            directory,
            "--target",
            target,
            "--destination",
            destination,
        ],
        export,
    )


def platform_target():
    uname = os.uname()
    machine = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}.get(uname.machine)
    require(machine is not None, f"unsupported host architecture: {uname.machine}")
    if uname.sysname == "Darwin":
        return f"{machine}-apple-darwin"
    if uname.sysname == "Linux":
        return f"{machine}-unknown-linux-gnu"
    raise ExportError(f"unsupported host system: {uname.sysname}")


def dynamic_library_name():
    return "libhop.dylib" if os.uname().sysname == "Darwin" else "libhop.so"


def go_module_metadata_path(relative):
    parts = PurePosixPath(relative).parts
    return any(part in GO_MODULE_METADATA_DIRECTORIES for part in parts) or any(
        parts[: len(prefix)] == prefix for prefix in GO_MODULE_METADATA_PREFIXES
    )


def go_module_files(export):
    export = Path(export).resolve()
    for directory, child_directories, filenames in os.walk(export):
        directory = Path(directory)
        parent = directory.relative_to(export)
        child_directories[:] = sorted(
            name
            for name in child_directories
            if not go_module_metadata_path((parent / name).as_posix())
        )
        for name in sorted(filenames):
            path = directory / name
            relative = path.relative_to(export).as_posix()
            if go_module_metadata_path(relative):
                continue
            require("\\" not in relative and "\x00" not in relative, f"Go module zip path is malformed: {relative!r}")
            normalized = PurePosixPath(relative)
            require(
                not normalized.is_absolute()
                and normalized.as_posix() == relative
                and all(part not in ("", ".", "..") for part in normalized.parts),
                f"Go module zip path is not normalized: {relative!r}",
            )
            require(path.is_file() and not path.is_symlink(), f"Go module zip input is not a regular file: {relative}")
            yield path, relative


def build_go_proxy(export, work, version):
    module = "github.com/hopmesh/hop-sdk-go"
    version_dir = work / "go-proxy" / module / "@v"
    version_dir.mkdir(parents=True)
    (version_dir / "list").write_text(version + "\n", encoding="utf-8")
    (version_dir / f"{version}.info").write_text(
        json.dumps({"Version": version, "Time": "2026-01-01T00:00:00Z"}) + "\n",
        encoding="utf-8",
    )
    shutil.copyfile(export / "go.mod", version_dir / f"{version}.mod")
    archive = version_dir / f"{version}.zip"
    prefix = f"{module}@{version}/"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for path, relative in go_module_files(export):
            output.write(path, prefix + relative)
    return version_dir.parent.parent.parent.parent, archive, prefix


def chmod_tree(root, directory_mode, file_mode):
    root = Path(root)
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=directory_mode & stat.S_IWUSR != 0):
        path.chmod(directory_mode if path.is_dir() else file_mode)
    root.chmod(directory_mode)


def tree_fingerprint(root, excluded_top_level=()):
    digest = __import__("hashlib").sha256()
    for path in sorted(candidate for candidate in Path(root).rglob("*") if candidate.is_file()):
        relative = path.relative_to(root)
        if relative.parts[0] in excluded_top_level:
            continue
        digest.update(relative.as_posix().encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def tree_modes(root, excluded_top_level=()):
    root = Path(root)
    paths = [root]
    paths.extend(
        path
        for path in root.rglob("*")
        if path.relative_to(root).parts[0] not in excluded_top_level and not path.is_symlink()
    )
    return {path: stat.S_IMODE(path.stat().st_mode) for path in paths}


def make_tree_read_only(modes):
    for path in sorted(modes, key=lambda item: len(item.parts), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)


def restore_tree_modes(modes):
    for path in sorted(modes, key=lambda item: len(item.parts)):
        path.chmod(modes[path])


def validate_go(export, work, bundle, target, public_key=None):
    helper_path = export / "native/native-artifacts.py"
    spec = importlib.util.spec_from_file_location("go_native_artifacts", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    manifest_path, signature, directory = native_paths(bundle)
    trusted_key = Path(public_key).resolve() if public_key else export / "native/native-artifacts-public.pem"
    manifest = helper.verify_release(
        manifest_path,
        signature,
        trusted_key,
        directory,
        target,
    )
    version = manifest["tag"]
    proxy, module_zip, zip_prefix = build_go_proxy(export, work, version)
    with zipfile.ZipFile(module_zip) as source:
        names = set(source.namelist())
    required_zip = {
        zip_prefix + "go.mod",
        zip_prefix + "hop.h",
        zip_prefix + "cmd/hop-install/main.go",
        zip_prefix + "cmd/hop-install/native-artifacts-public.pem",
    }
    require(required_zip <= names, f"Go module zip is incomplete: {sorted(required_zip - names)}")
    require(not any("/native/lib/" in name or name.endswith("install-libhop.py") for name in names), "Go module zip contains a checkout-local installer or native library")

    artifact = helper.select_artifact(manifest, target)
    archive = directory / artifact["filename"]
    with tarfile.open(archive, "r:gz") as source:
        release_names = {member.name for member in source.getmembers() if member.isfile()}
    expected_release = {"include/hop.h", "lib/" + dynamic_library_name()}
    require(release_names == expected_release, f"Go release artifact contents differ: {sorted(release_names)}")

    consumer = work / "go-consumer"
    consumer.mkdir()
    (consumer / "go.mod").write_text(
        f"module clean.example/go-consumer\n\ngo 1.21\n\nrequire github.com/hopmesh/hop-sdk-go {version}\n",
        encoding="utf-8",
    )
    (consumer / "main.go").write_text(
        'package main\n\nimport (\n  "fmt"\n  "net/http"\n  hop "github.com/hopmesh/hop-sdk-go"\n)\n\n'
        "func main() { server, err := hop.New(); if err != nil { panic(err) }; defer server.Close(); "
        "httpServer := hop.NewHTTPServer(\"\", http.NotFoundHandler()); "
        "if err := server.Attach(httpServer, \"wss://example.invalid/_hop\"); err != nil { panic(err) }; "
        "fmt.Println(server.Address()) }\n",
        encoding="utf-8",
    )
    (consumer / "main_test.go").write_text(
        'package main\n\nimport (\n  "testing"\n  hop "github.com/hopmesh/hop-sdk-go"\n)\n\n'
        "func TestImport(t *testing.T) { if hop.NewHTTPServer(\"\", nil) == nil { t.Fatal(\"nil server\") } }\n",
        encoding="utf-8",
    )

    module_cache = work / "go-mod-cache"
    build_cache = work / "go-build-cache"
    prefix = work / "native-prefix"
    env = dict(os.environ)
    env.update(
        {
            "GOCACHE": str(build_cache),
            "GOMODCACHE": str(module_cache),
            "GONOSUMDB": "*",
            "GOPROXY": proxy.as_uri() + ",https://proxy.golang.org",
            "GOSUMDB": "off",
        }
    )
    run(["go", "mod", "download", "all"], consumer, env)
    require("replace " not in (consumer / "go.mod").read_text(encoding="utf-8"), "clean Go consumer uses replace")
    before = tree_fingerprint(module_cache)
    chmod_tree(module_cache, 0o555, 0o444)

    install = [
        "go",
        "run",
        f"github.com/hopmesh/hop-sdk-go/cmd/hop-install@{version}",
        "--version",
        version,
        "--target",
        target,
        "--bundle",
        bundle,
        "--source-sha",
        manifest["source_sha"],
        "--prefix",
        prefix,
    ]
    if public_key:
        install.extend(["--public-key", trusted_key])
    try:
        run(install, work, env)
        require(tree_fingerprint(module_cache) == before, "Go installer modified the read-only module cache")
        install_root = prefix / version
        library = install_root / "lib" / dynamic_library_name()
        pkg_config = install_root / "lib/pkgconfig/hop.pc"
        require(library.is_file() and pkg_config.is_file(), "Go installer omitted libhop or hop.pc")
        require((install_root / "include/hop.h").read_bytes() == (export / "hop.h").read_bytes(), "installed header differs from module header")
        require(str(install_root) in pkg_config.read_text(encoding="utf-8"), "hop.pc does not declare the stable prefix")

        env["PKG_CONFIG_PATH"] = str(pkg_config.parent)
        loader = "DYLD_LIBRARY_PATH" if os.uname().sysname == "Darwin" else "LD_LIBRARY_PATH"
        env[loader] = str(library.parent)
        run(["go", "mod", "tidy"], consumer, env)
        run(["go", "vet", "./..."], export, env)
        run(["go", "test", "./..."], export, env)
        run(["go", "test", "./..."], consumer, env)
        run(["go", "build", "./..."], consumer, env)
        run(["go", "run", "."], consumer, env)
        run(["go", "mod", "vendor"], consumer, env)
        require(tree_fingerprint(module_cache) == before, "clean Go validation modified the read-only module cache")
    finally:
        chmod_tree(module_cache, 0o755, 0o644)

    vendored = consumer / "vendor/github.com/hopmesh/hop-sdk-go/hop.h"
    require(vendored.is_file(), "Go module archive/vendor output omitted hop.h")
    require(not any(path.name == dynamic_library_name() for path in module_cache.rglob("*")), "Go module cache contains an installed native library")
    print(
        "Go export validated: signed prefix install, read-only module cache, "
        f"proxy consumer test/build/run, module_zip={module_zip}, release={archive}"
    )


def mix_command(export, *arguments):
    env = dict(os.environ)
    if shutil.which("mix"):
        return ["mix", *arguments], env
    env["MISE_CONFIG_FILE"] = str(export / ".mise.toml")
    return ["mise", "exec", "--", "mix", *arguments], env


def inspect_hex_package(package, destination):
    with tarfile.open(package) as outer:
        member = outer.getmember("contents.tar.gz")
        require(member.isfile(), "Hex contents.tar.gz is not a regular file")
        payload = outer.extractfile(member)
        require(payload is not None, "Hex contents.tar.gz cannot be read")
        contents = payload.read()
    destination = Path(destination)
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(contents), mode="r:gz") as inner:
        names = set()
        for member in inner.getmembers():
            if member.isdir():
                continue
            relative = PurePosixPath(member.name)
            require(
                member.isfile() and not relative.is_absolute() and ".." not in relative.parts,
                f"Hex package contains an unsafe member: {member.name}",
            )
            require(member.name not in names, f"Hex package contains a duplicate member: {member.name}")
            names.add(member.name)
            extracted = inner.extractfile(member)
            require(extracted is not None, f"Hex package member cannot be read: {member.name}")
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(extracted.read())
    required = {
        "mix.exs",
        "native/Cargo.toml",
        "native/Cargo.lock",
        "native/hop_endpoint/Cargo.toml",
        "native/hop_endpoint/src/lib.rs",
        "native/vendor/libhop/src/lib.rs",
        "native/vendor/hop-core/src/lib.rs",
        "native/vendor/hop-endpoint-core/src/lib.rs",
        "native/vendor/hop-store-sqlite/src/lib.rs",
    }
    require(required <= names, f"Hex package omitted native source: {sorted(required - names)}")
    require(not any(name.startswith("priv/native/") for name in names), "Hex package contains a host NIF binary")
    return names


def cargo_dependency_tables(document):
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        yield section, document.get(section, {})
    workspace = document.get("workspace", {})
    yield "workspace.dependencies", workspace.get("dependencies", {})
    for target, target_value in document.get("target", {}).items():
        if not isinstance(target_value, dict):
            continue
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            yield f"target.{target}.{section}", target_value.get(section, {})
    for registry, patch in document.get("patch", {}).items():
        yield f"patch.{registry}", patch
    yield "replace", document.get("replace", {})


def normalized_cargo_crate_path(export, manifest, raw, label):
    require(isinstance(raw, str) and raw, f"{label} is empty")
    require("\\" not in raw and "\x00" not in raw, f"{label} is malformed: {raw!r}")
    relative = PurePosixPath(raw)
    require(not relative.is_absolute() and not re.match(r"^[A-Za-z]:/", raw), f"{label} is absolute: {raw!r}")
    require(
        relative.as_posix() == raw and all(part not in ("", ".", "..") for part in relative.parts),
        f"{label} is not normalized: {raw!r}",
    )
    candidate = manifest.parent.joinpath(*relative.parts)
    require(candidate.is_dir(), f"{label} crate is missing: {raw!r}")
    resolved = candidate.resolve()
    export = Path(export).resolve()
    require(resolved == export or export in resolved.parents, f"{label} escapes the package root: {raw!r}")
    crate_manifest = resolved / "Cargo.toml"
    require(crate_manifest.is_file(), f"{label} crate has no Cargo.toml: {raw!r}")
    resolved_manifest = crate_manifest.resolve()
    require(
        resolved_manifest == export or export in resolved_manifest.parents,
        f"{label} Cargo.toml escapes the package root: {raw!r}",
    )
    return resolved_manifest


def elixir_declared_cargo_manifests(export):
    export = Path(export).resolve()
    native = export / "native"
    require(native.is_dir(), "Elixir native package root is missing")
    local_manifests = set()
    manifests = sorted(native.rglob("Cargo.toml"))
    require(manifests, "Elixir package contains no Cargo manifests")
    for manifest in manifests:
        resolved_manifest = manifest.resolve()
        require(
            resolved_manifest == export or export in resolved_manifest.parents,
            f"Elixir Cargo manifest escapes the package root: {manifest}",
        )
        try:
            document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise ExportError(f"Elixir Cargo manifest cannot be parsed: {manifest}: {error}") from error
        for section, dependencies in cargo_dependency_tables(document):
            require(isinstance(dependencies, dict), f"Elixir Cargo dependency table is malformed: {manifest}: {section}")
            for dependency, specification in dependencies.items():
                if isinstance(specification, dict) and "path" in specification:
                    label = f"Elixir Cargo path dependency {manifest}:{section}.{dependency}"
                    local_manifests.add(
                        normalized_cargo_crate_path(export, manifest, specification["path"], label)
                    )
        workspace = document.get("workspace", {})
        members = workspace.get("members", []) if isinstance(workspace, dict) else []
        require(isinstance(members, list), f"Elixir Cargo workspace members are malformed: {manifest}")
        for member in members:
            label = f"Elixir Cargo workspace member {manifest}"
            local_manifests.add(normalized_cargo_crate_path(export, manifest, member, label))
        package = document.get("package", {})
        workspace_path = package.get("workspace") if isinstance(package, dict) else None
        if workspace_path is not None:
            label = f"Elixir Cargo package workspace {manifest}"
            local_manifests.add(normalized_cargo_crate_path(export, manifest, workspace_path, label))
    return local_manifests


def validate_elixir_cargo_metadata(export, declared, metadata):
    export = Path(export).resolve()
    require(isinstance(metadata, dict) and isinstance(metadata.get("packages"), list), "Cargo metadata is malformed")
    metadata_manifests = set()
    for package in metadata["packages"]:
        if not isinstance(package, dict) or package.get("source") is not None:
            continue
        raw_manifest = package.get("manifest_path")
        require(isinstance(raw_manifest, str), "Cargo metadata local package has no manifest path")
        manifest = Path(raw_manifest).resolve()
        require(
            manifest.is_file() and (manifest == export or export in manifest.parents),
            f"Cargo metadata resolved a local package outside the export: {raw_manifest}",
        )
        metadata_manifests.add(manifest)
    missing = declared - metadata_manifests
    require(not missing, f"Cargo metadata omitted declared package-local crates: {sorted(str(path) for path in missing)}")


def validate_elixir_cargo(export):
    export = Path(export).resolve()
    declared = elixir_declared_cargo_manifests(export)
    metadata = json.loads(
        run(
            ["cargo", "metadata", "--locked", "--manifest-path", "native/Cargo.toml", "--format-version", "1"],
            export,
            capture=True,
        )
    )
    validate_elixir_cargo_metadata(export, declared, metadata)


def validate_elixir(export, work):
    lock_path = export / "native/Cargo.lock"
    locked = lock_path.read_bytes()
    validate_elixir_cargo(export)
    command, env = mix_command(export, "local.hex", "2.2.1", "--force")
    run(command, export, env)
    command, env = mix_command(export, "deps.get")
    run(command, export, env)
    command, env = mix_command(export, "test")
    run(command, export, env)
    require(lock_path.read_bytes() == locked, "Elixir build modified the packaged Cargo.lock")
    package = work / "hop_endpoint-0.0.1.tar"
    command, env = mix_command(export, "hex.build", "--output", str(package))
    run(command, export, env)
    extracted_package = work / "hex-package"
    names = inspect_hex_package(package, extracted_package)
    consumer = work / "elixir-consumer"
    (consumer / "test").mkdir(parents=True)
    (consumer / "mix.exs").write_text(
        "defmodule CleanConsumer.MixProject do\n  use Mix.Project\n"
        "  def project, do: [app: :clean_consumer, version: \"0.0.0\", elixir: \"~> 1.15\", deps: deps()]\n"
        f"  defp deps, do: [{{:hop_endpoint, path: {json.dumps(str(extracted_package))}}}]\nend\n",
        encoding="utf-8",
    )
    (consumer / "test/test_helper.exs").write_text("ExUnit.start()\n", encoding="utf-8")
    (consumer / "test/import_test.exs").write_text(
        "defmodule CleanConsumer.ImportTest do\n  use ExUnit.Case\n"
        "  test \"loads package\", do: assert(Code.ensure_loaded?(Hop.Endpoint))\nend\n",
        encoding="utf-8",
    )
    command, env = mix_command(export, "deps.get")
    run(command, consumer, env)
    command, env = mix_command(export, "test")
    run(command, consumer, env)
    print(f"Elixir export validated: tests, clean consumer, Hex files={len(names)}, archive={package}")


def package_checksum(package):
    return run(["swift", "package", "compute-checksum", package], package.parent, capture=True)


def validate_apple(export, work, bundle):
    dumped = run(["swift", "package", "dump-package"], export, capture=True)
    manifest = json.loads(dumped)
    binary = next(target for target in manifest["targets"] if target["name"] == "CHop")
    require(binary.get("url", "").startswith("https://github.com/hopmesh/hop-sdk-apple/releases/download/v0.0.1/"), "published Apple manifest does not use its immutable release URL")
    expected_checksum = binary.get("checksum")
    require(isinstance(expected_checksum, str) and re.fullmatch(r"[0-9a-f]{64}", expected_checksum), "published Apple checksum is invalid")
    helper_path = export / "native/native-artifacts.py"
    spec = importlib.util.spec_from_file_location("apple_native_artifacts", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    manifest_path, signature, directory = native_paths(bundle)
    manifest_value = helper.verify_release(
        manifest_path,
        signature,
        export / "native/native-artifacts-public.pem",
        directory,
        "apple-xcframework",
    )
    artifact = helper.select_artifact(manifest_value, "apple-xcframework")
    archive = directory / artifact["filename"]
    require(package_checksum(archive) == expected_checksum, "Package.swift checksum does not match verified Apple artifact")
    slices = ("ios-arm64", "ios-arm64_x86_64-simulator", "macos-arm64_x86_64")
    expected_files = {"libhop.xcframework/Info.plist", "libhop.xcframework/architecture-manifest.json"}
    for slice_name in slices:
        expected_files.update(
            {
                f"libhop.xcframework/{slice_name}/Headers/hop.h",
                f"libhop.xcframework/{slice_name}/Headers/module.modulemap",
                f"libhop.xcframework/{slice_name}/libhop.a",
            }
        )
    declared_files = {entry["path"] for entry in artifact["archive"]["files"]}
    require(declared_files == expected_files, f"Apple release archive inventory differs: {sorted(declared_files)}")
    with zipfile.ZipFile(archive) as source:
        headers = [source.read(f"libhop.xcframework/{slice_name}/Headers/hop.h") for slice_name in slices]
        module_maps = [source.read(f"libhop.xcframework/{slice_name}/Headers/module.modulemap") for slice_name in slices]
    require(len(set(headers)) == 1, "Apple xcframework slice headers differ")
    require(b"#define HOP_ABI_VERSION 4\n" in headers[0], "Apple xcframework does not expose ABI 4")
    require(len(set(module_maps)) == 1 and b"module CHop {" in module_maps[0], "Apple xcframework module maps differ")
    run(["python3", "install-local-xcframework.py", "--version", "v0.0.1", "--bundle", bundle], export)
    frameworks = export / "Frameworks"
    xcframework = frameworks / "libhop.xcframework"
    run(
        [
            "python3",
            export / "native/native-artifacts.py",
            "apple-verify",
            "--xcframework",
            xcframework,
            "--manifest",
            xcframework / "architecture-manifest.json",
        ],
        export,
    )
    repacked = work / "libhop.xcframework.repacked.zip"
    helper.pack_archive(frameworks, ["libhop.xcframework"], repacked, "zip")
    require(repacked.read_bytes() == archive.read_bytes(), "Apple release archive is not a deterministic repack")
    shutil.copyfile(export / "Package.local.swift", export / "Package.swift")
    run(["swift", "test"], export)
    consumer = work / "apple-consumer"
    (consumer / "Sources/CleanConsumer").mkdir(parents=True)
    (consumer / "Package.swift").write_text(
        "// swift-tools-version:5.9\nimport PackageDescription\n"
        "let package = Package(name: \"CleanConsumer\", platforms: [.macOS(.v13)], "
        f"dependencies: [.package(path: {json.dumps(str(export))})], "
        "targets: [.executableTarget(name: \"CleanConsumer\", dependencies: [.product(name: \"Hop\", package: \"export\")])])\n",
        encoding="utf-8",
    )
    (consumer / "Sources/CleanConsumer/main.swift").write_text(
        "import Foundation\nimport Hop\nprint(HopAddress.base58(Data(repeating: 0, count: 32)))\n",
        encoding="utf-8",
    )
    run(["swift", "package", "resolve"], consumer)
    run(["swift", "build"], consumer)
    print(f"Apple export validated: inventory, deterministic zip, checksum, architectures, ABI, tests, binary consumer, artifact={archive}")


def write_android_application(project, dependency, source, repository=None, resolved_hop_version=None):
    project = Path(project)
    (project / "app/src/main/kotlin/example/clean").mkdir(parents=True)
    repositories = "        google()\n        mavenCentral()\n"
    if repository is not None:
        repositories = (
            "        exclusiveContent {\n"
            "            forRepository {\n"
            "                maven {\n"
            '                    name = "hopPackage"\n'
            f"                    url = uri({json.dumps(str(Path(repository).resolve()))})\n"
            "                }\n"
            "            }\n"
            '            filter { includeGroup("sh.hop") }\n'
            "        }\n"
            + repositories
        )
    (project / "settings.gradle.kts").write_text(
        "import org.gradle.api.initialization.resolve.RepositoriesMode\n\n"
        "pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }\n"
        "dependencyResolutionManagement {\n"
        "    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)\n"
        "    repositories {\n"
        + repositories
        + "    }\n"
        "}\n"
        'rootProject.name = "clean-android-consumer"\n'
        'include(":app")\n',
        encoding="utf-8",
    )
    (project / "build.gradle.kts").write_text(
        "plugins {\n"
        f'    id("com.android.application") version "{ANDROID_AGP_VERSION}" apply false\n'
        f'    id("org.jetbrains.kotlin.android") version "{ANDROID_KOTLIN_VERSION}" apply false\n'
        "}\n",
        encoding="utf-8",
    )
    (project / "gradle.properties").write_text(
        "org.gradle.jvmargs=-Xmx2048m\n"
        "android.useAndroidX=true\n"
        "kotlin.code.style=official\n"
        "android.builtInKotlin=false\n"
        "android.newDsl=false\n",
        encoding="utf-8",
    )
    report_task = ""
    if resolved_hop_version is not None:
        report_task = (
            "\nval resolvedHopAar = layout.buildDirectory.file(\"reports/resolved-hop-aar.txt\")\n"
            'tasks.register("writeResolvedHopAar") {\n'
            "    outputs.file(resolvedHopAar)\n"
            "    doLast {\n"
            '        val artifacts = configurations.getByName("debugRuntimeClasspath")\n'
            "            .incoming.artifacts.resolvedArtifacts.get().filter { artifact ->\n"
            "                val component = artifact.id.componentIdentifier as? ModuleComponentIdentifier\n"
            f'                component?.group == "sh.hop" && component.module == "hop" && component.version == "{resolved_hop_version}"\n'
            "            }\n"
            '        require(artifacts.size == 1) { "expected one resolved sh.hop:hop AAR, found $artifacts" }\n'
            "        val artifact = artifacts.single().file\n"
            '        require(artifact.extension == "aar") { "resolved Hop artifact is not an AAR: $artifact" }\n'
            "        val output = resolvedHopAar.get().asFile\n"
            "        output.parentFile.mkdirs()\n"
            '        output.writeText(artifact.canonicalPath + "\\n")\n'
            "    }\n"
            "}\n"
        )
    (project / "app/build.gradle.kts").write_text(
        "import org.gradle.api.artifacts.component.ModuleComponentIdentifier\n"
        "import org.jetbrains.kotlin.gradle.dsl.JvmTarget\n\n"
        "plugins {\n"
        '    id("com.android.application")\n'
        '    id("org.jetbrains.kotlin.android")\n'
        "}\n\n"
        "android {\n"
        '    namespace = "example.clean"\n'
        f"    compileSdk = {ANDROID_COMPILE_SDK}\n"
        "    defaultConfig {\n"
        '        applicationId = "example.clean"\n'
        "        minSdk = 23\n"
        f"        targetSdk = {ANDROID_COMPILE_SDK}\n"
        "        versionCode = 1\n"
        '        versionName = "1.0"\n'
        "    }\n"
        "    compileOptions {\n"
        "        sourceCompatibility = JavaVersion.VERSION_1_8\n"
        "        targetCompatibility = JavaVersion.VERSION_1_8\n"
        "    }\n"
        "}\n"
        "kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_1_8) } }\n\n"
        f"dependencies {{ {dependency} }}\n"
        + report_task,
        encoding="utf-8",
    )
    (project / "app/src/main/AndroidManifest.xml").parent.mkdir(parents=True, exist_ok=True)
    (project / "app/src/main/AndroidManifest.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '    <application android:label="Clean Hop Consumer" android:theme="@android:style/Theme.Material.Light.NoActionBar">\n'
        '        <activity android:name=".MainActivity" android:exported="true">\n'
        "            <intent-filter>\n"
        '                <action android:name="android.intent.action.MAIN" />\n'
        '                <category android:name="android.intent.category.LAUNCHER" />\n'
        "            </intent-filter>\n"
        "        </activity>\n"
        "    </application>\n"
        "</manifest>\n",
        encoding="utf-8",
    )
    (project / "app/src/main/kotlin/example/clean/MainActivity.kt").write_text(source, encoding="utf-8")


def elf_machine(payload):
    require(len(payload) >= 20 and payload[:4] == b"\x7fELF", "Android native library is not ELF")
    byte_order = {1: "little", 2: "big"}.get(payload[5])
    require(byte_order is not None, "Android native library has an invalid ELF byte order")
    return int.from_bytes(payload[18:20], byte_order)


def android_version(export):
    text = (Path(export) / "build.gradle.kts").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', text, re.MULTILINE)
    require(match is not None, "Android publication version is missing")
    return match.group(1)


def validate_android(export, work, bundle):
    export = Path(export).resolve()
    work = Path(work).resolve()
    version = android_version(export)
    repository = work / "android-maven"
    env = dict(os.environ)
    local_jdk = Path("/opt/homebrew/opt/openjdk@17")
    if "JAVA_HOME" not in env and local_jdk.joinpath("bin/java").is_file():
        env["JAVA_HOME"] = str(local_jdk)
        env["PATH"] = str(local_jdk / "bin") + os.pathsep + env["PATH"]

    gradle_version = run(["gradle", "--version"], export, env, capture=True)
    match = re.search(r"^Gradle ([0-9.]+)$", gradle_version, re.MULTILINE)
    require(match is not None and match.group(1) == ANDROID_GRADLE_VERSION, f"Android proof requires Gradle {ANDROID_GRADLE_VERSION}")

    # Fetch the pinned plugin and external dependency graph before publication. Every operation after
    # build-aar.sh completes is --offline, so the consumer cannot fall through to a public Hop package.
    warmup = work / "android-toolchain-warmup"
    write_android_application(
        warmup,
        'implementation("net.java.dev.jna:jna:5.19.1@aar")',
        "package example.clean\nimport android.app.Activity\nclass MainActivity : Activity()\n",
    )
    run(["gradle", ":app:assembleDebug", ":app:lintDebug", "--no-daemon"], warmup, env)
    shutil.rmtree(warmup)

    run(["bash", "build-aar.sh", "--bundle", bundle, "--repository", repository], export, env)
    version_dir = repository / "sh/hop/hop" / version
    aar = version_dir / f"hop-{version}.aar"
    require(aar.is_file(), "Android local Maven publication omitted the AAR")
    with zipfile.ZipFile(aar) as source:
        names = set(source.namelist())
        required = {
            "AndroidManifest.xml",
            "classes.jar",
            "prefab/prefab.json",
            "prefab/modules/libhop/module.json",
            "prefab/modules/libhop/include/hop.h",
        }
        required.update(f"jni/{abi}/libhop.so" for abi in ANDROID_ABIS)
        required.update(f"prefab/modules/libhop/libs/android.{abi}/libhop.so" for abi in ANDROID_ABIS)
        required.update(f"prefab/modules/libhop/libs/android.{abi}/abi.json" for abi in ANDROID_ABIS)
        require(required <= names, f"AAR contents are incomplete: {sorted(required - names)}")
        aar_manifest = source.read("AndroidManifest.xml").decode("utf-8")
        require('package="sh.hop"' in aar_manifest, "AAR manifest does not declare the sh.hop package")
        require('android:minSdkVersion="23"' in aar_manifest, "AAR manifest does not declare minSdk 23")
        prefab = json.loads(source.read("prefab/prefab.json"))
        require(prefab == {"name": "hop", "schema_version": 2, "version": version}, "AAR Prefab package metadata differs")
        module = json.loads(source.read("prefab/modules/libhop/module.json"))
        require(module.get("library_name") == "libhop", "AAR Prefab module metadata differs")
        require(source.read("prefab/modules/libhop/include/hop.h") == (export / "include/hop.h").read_bytes(), "AAR Prefab header differs from the export")
        for abi, expected_machine in ANDROID_ABIS.items():
            metadata = json.loads(source.read(f"prefab/modules/libhop/libs/android.{abi}/abi.json"))
            require(metadata.get("abi") == abi and metadata.get("api") == 23, f"AAR Prefab ABI metadata differs for {abi}")
            native = source.read(f"jni/{abi}/libhop.so")
            require(elf_machine(native) == expected_machine, f"AAR libhop.so has the wrong ELF machine for {abi}")
            require(native == source.read(f"prefab/modules/libhop/libs/android.{abi}/libhop.so"), f"AAR JNI and Prefab slices differ for {abi}")

    published = (
        aar,
        version_dir / f"hop-{version}-sources.jar",
        version_dir / f"hop-{version}-javadoc.jar",
        version_dir / f"hop-{version}.pom",
    )
    for artifact in published:
        require(artifact.is_file() and artifact.stat().st_size > 0, f"Android publication omitted {artifact.name}")
        for algorithm in ("sha256", "sha512"):
            sidecar = artifact.with_name(artifact.name + "." + algorithm)
            require(sidecar.is_file(), f"Android publication omitted {sidecar.name}")
            actual = __import__("hashlib").new(algorithm, artifact.read_bytes()).hexdigest()
            require(sidecar.read_text(encoding="utf-8").strip() == actual, f"Android publication has a wrong {algorithm} for {artifact.name}")
    pom = (version_dir / f"hop-{version}.pom").read_text(encoding="utf-8")
    for marker in ("<packaging>aar</packaging>", "<artifactId>jna</artifactId>", "<type>aar</type>"):
        require(marker in pom, f"Android POM is missing {marker}")

    consumer = work / "android-consumer"
    write_android_application(
        consumer,
        f'implementation("sh.hop:hop:{version}")',
        "package example.clean\n"
        "import android.app.Activity\n"
        "import android.os.Bundle\n"
        "import sh.hop.HopAddress\n"
        "class MainActivity : Activity() {\n"
        "    override fun onCreate(state: Bundle?) {\n"
        "        super.onCreate(state)\n"
        "        title = HopAddress.base58(ByteArray(32))\n"
        "    }\n"
        "}\n",
        repository,
        version,
    )
    consumer_text = "\n".join(path.read_text(encoding="utf-8") for path in sorted(consumer.rglob("*")) if path.is_file())
    require(consumer_text.count("implementation(") == 1, "clean Android consumer must declare exactly one dependency")
    require(f'implementation("sh.hop:hop:{version}")' in consumer_text, "clean Android consumer lacks the Maven coordinate")
    for marker in ("zipTree(", "implementation(files(", "@aar", "includeBuild(", "project(", str(export)):
        require(marker not in consumer_text, f"clean Android consumer contains forbidden source or archive wiring: {marker}")

    source_excludes = {".git", ".gradle", ".kotlin", "build"}
    export_fingerprint = tree_fingerprint(export, source_excludes)
    repository_fingerprint = tree_fingerprint(repository)
    export_modes = tree_modes(export, source_excludes)
    repository_modes = tree_modes(repository)
    try:
        make_tree_read_only(export_modes)
        make_tree_read_only(repository_modes)
        dependency_report = run(
            [
                "gradle",
                ":app:dependencyInsight",
                "--dependency",
                "sh.hop:hop",
                "--configuration",
                "debugRuntimeClasspath",
                "--offline",
                "--no-daemon",
            ],
            consumer,
            env,
            capture=True,
        )
        require(f"sh.hop:hop:{version}" in dependency_report, "Android dependency report omitted the Hop Maven coordinate")
        run(
            [
                "gradle",
                ":app:writeResolvedHopAar",
                ":app:lintDebug",
                ":app:assembleDebug",
                "--offline",
                "--no-daemon",
                "--stacktrace",
            ],
            consumer,
            env,
        )
        require(tree_fingerprint(export, source_excludes) == export_fingerprint, "clean Android consumer modified the exported SDK")
        require(tree_fingerprint(repository) == repository_fingerprint, "clean Android consumer modified the Maven repository")
    finally:
        restore_tree_modes(repository_modes)
        restore_tree_modes(export_modes)

    resolved_path = consumer / "app/build/reports/resolved-hop-aar.txt"
    require(resolved_path.is_file(), "Android consumer did not report its resolved Hop AAR")
    resolved_aar = Path(resolved_path.read_text(encoding="utf-8").strip())
    require(resolved_aar.is_file() and resolved_aar.read_bytes() == aar.read_bytes(), "Android consumer resolved a different Hop AAR")

    merger_logs = list((consumer / "app/build").rglob("manifest-merger-*-report.txt"))
    merge_marker = f"MERGED from [sh.hop:hop:{version}]"
    require(merger_logs and any(merge_marker in path.read_text(encoding="utf-8") for path in merger_logs), "Android manifest merger did not consume the Hop AAR")
    merged_manifests = []
    for path in (consumer / "app/build/intermediates").rglob("AndroidManifest.xml"):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if 'package="example.clean"' in text and "example.clean.MainActivity" in text:
            merged_manifests.append(text)
    require(merged_manifests, "Android consumer has no merged application manifest")
    require(any('android:minSdkVersion="23"' in text for text in merged_manifests), "merged Android manifest omitted the AAR minSdk metadata")

    apk = consumer / "app/build/outputs/apk/debug/app-debug.apk"
    require(apk.is_file(), "clean Android consumer did not assemble a debug APK")
    with zipfile.ZipFile(aar) as aar_source, zipfile.ZipFile(apk) as apk_source:
        apk_names = set(apk_source.namelist())
        require("AndroidManifest.xml" in apk_names and any(re.fullmatch(r"classes[0-9]*\.dex", name) for name in apk_names), "debug APK lacks manifest or DEX metadata")
        for abi in ANDROID_ABIS:
            apk_name = f"lib/{abi}/libhop.so"
            require(apk_name in apk_names, f"debug APK omitted {apk_name}")
            require(apk_source.read(apk_name) == aar_source.read(f"jni/{abi}/libhop.so"), f"debug APK changed the {abi} libhop slice")
    print(
        "Android export validated: signed native inputs, real Maven publication, resolved AAR, "
        f"offline AGP dependency/lint/APK consumer, artifact={aar}, apk={apk}"
    )


def validate_embedded(export, work, bundle, target):
    run(["bash", "test/run-host-tests.sh"], export)
    extracted = work / "embedded-host"
    extract_target(export, bundle, target, extracted)
    library = extracted / "lib" / dynamic_library_name()
    require(library.is_file(), "embedded host fixture lacks libhop dynamic library")
    consumer = work / "embedded-consumer.cpp"
    consumer.write_text(
        '#include "Hop.h"\n#include <cstdint>\nint main() { hop::Hop node; if (!node.begin()) return 1; return node.synchronizeClock(1700000000000ULL, 1) == hop::ClockStatus::Ready ? 0 : 2; }\n',
        encoding="utf-8",
    )
    executable = work / "embedded-consumer"
    command = ["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", export / "src", export / "src/Hop.cpp", consumer, library, "-o", executable]
    if os.uname().sysname == "Darwin":
        command.extend(["-Wl,-rpath," + str(library.parent)])
    else:
        command.extend(["-Wl,-rpath," + str(library.parent), "-ldl", "-lpthread"])
    run(command, export)
    run([executable], export)
    helper_path = export / "native/native-artifacts.py"
    spec = importlib.util.spec_from_file_location("embedded_native_artifacts", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    manifest_path, signature, directory = native_paths(bundle)
    helper.verify_signature(manifest_path, signature, export / "native/native-artifacts-public.pem")
    manifest_value = helper.load_manifest(manifest_path)
    embedded_targets = {
        "xtensa-esp32-espidf",
        "xtensa-esp32s2-espidf",
        "xtensa-esp32s3-espidf",
        "riscv32imc-esp-espidf",
        "riscv32imac-esp-espidf",
    }
    selected = [artifact for artifact in manifest_value["artifacts"] if artifact["target"] in embedded_targets]
    require({artifact["target"] for artifact in selected} == embedded_targets, "fixture release lacks an exact embedded target")
    run(
        [
            sys.executable,
            export / "install-libhop.py",
            "--version",
            manifest_value["tag"],
            "--bundle",
            directory,
        ],
        export,
    )
    package = work / "hop-embedded.tar.gz"
    run(["pio", "pkg", "pack", "--output", package], export)
    with tarfile.open(package, "r:gz") as source:
        names = {member.name for member in source.getmembers()}
    required_suffixes = {
        "src/Hop.cpp",
        "install-libhop.py",
        "native/native-artifacts.py",
        "native/native-artifacts.json",
        "native/native-artifacts.json.sig",
    }
    required_suffixes.update("native/artifacts/" + artifact["filename"] for artifact in selected)
    missing = {suffix for suffix in required_suffixes if not any(name.endswith(suffix) for name in names)}
    require(not missing, f"PlatformIO package archive is incomplete: {sorted(missing)}")
    print(f"Embedded export validated: host tests, signed fixture consumer, PlatformIO archive={package}")


def validate_package(root, work_root, component, bundle, host_target):
    work_root = Path(work_root).resolve()
    require(work_root.is_dir(), f"work root is missing: {work_root}")
    work = work_root / (component + "-validation")
    require(not work.exists(), f"validation directory already exists: {work}")
    work.mkdir()
    export = work / "export"
    export_component(root, component, export)
    if component == "hop-sdk-go":
        validate_go(export, work, bundle, host_target)
    elif component == "hop-sdk-elixir":
        validate_elixir(export, work)
    elif component == "hop-sdk-apple":
        validate_apple(export, work, bundle)
    elif component == "hop-sdk-android":
        validate_android(export, work, bundle)
    elif component == "hop-embedded":
        validate_embedded(export, work, bundle, host_target)
    else:
        raise ExportError(f"no clean package validator for {component}")


def validate_existing_go(export, work_root, bundle, host_target, public_key=None):
    export = Path(export).resolve()
    work_root = Path(work_root).resolve()
    require((export / "go.mod").is_file(), f"Go export is missing: {export}")
    require(work_root.is_dir(), f"work root is missing: {work_root}")
    work = work_root / "hop-sdk-go-validation"
    require(not work.exists(), f"validation directory already exists: {work}")
    work.mkdir()
    validate_go(export, work, bundle, host_target, public_key)


def validate_existing_android(export, work_root, bundle):
    export = Path(export).resolve()
    work_root = Path(work_root).resolve()
    require((export / "build-aar.sh").is_file(), f"Android export is missing: {export}")
    require(work_root.is_dir(), f"work root is missing: {work_root}")
    work = work_root / "hop-sdk-android-validation"
    require(not work.exists(), f"validation directory already exists: {work}")
    work.mkdir()
    validate_android(export, work, bundle)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    subparsers = parser.add_subparsers(dest="command", required=True)
    export = subparsers.add_parser("export")
    export.add_argument("--component", required=True)
    export.add_argument("--output", required=True)
    check = subparsers.add_parser("check")
    check.add_argument("--output-root", required=True)
    check.add_argument("--component", action="append", dest="components")
    validate = subparsers.add_parser("validate")
    validate.add_argument("--component", choices=PACKAGE_COMPONENTS, required=True)
    validate.add_argument("--work-root", required=True)
    validate.add_argument("--native-bundle")
    validate.add_argument("--host-target", default=platform_target())
    validate_go_export = subparsers.add_parser("validate-go-export")
    validate_go_export.add_argument("--export", default=".")
    validate_go_export.add_argument("--work-root", required=True)
    validate_go_export.add_argument("--native-bundle", required=True)
    validate_go_export.add_argument("--host-target", default=platform_target())
    validate_go_export.add_argument("--public-key")
    validate_elixir_export = subparsers.add_parser("validate-elixir-export")
    validate_elixir_export.add_argument("--export", default=".")
    validate_android_export = subparsers.add_parser("validate-android-export")
    validate_android_export.add_argument("--export", default=".")
    validate_android_export.add_argument("--work-root", required=True)
    validate_android_export.add_argument("--native-bundle", required=True)
    args = parser.parse_args()
    root = Path(args.root).resolve()
    try:
        if args.command == "export":
            export_component(root, args.component, Path(args.output).resolve())
        elif args.command == "check":
            selected = tuple(args.components or load_components(root).keys())
            static_check(root, args.output_root, selected)
        elif args.command == "validate":
            if args.component != "hop-sdk-elixir":
                require(args.native_bundle, f"{args.component} validation requires --native-bundle")
            validate_package(root, args.work_root, args.component, args.native_bundle, args.host_target)
        elif args.command == "validate-go-export":
            validate_existing_go(
                args.export,
                args.work_root,
                args.native_bundle,
                args.host_target,
                args.public_key,
            )
        elif args.command == "validate-elixir-export":
            validate_elixir_cargo(Path(args.export).resolve())
        elif args.command == "validate-android-export":
            validate_existing_android(args.export, args.work_root, args.native_bundle)
    except (ExportError, OSError, ValueError, json.JSONDecodeError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise SystemExit(f"package export rejected: {error}") from error


if __name__ == "__main__":
    main()
