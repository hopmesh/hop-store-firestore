#!/usr/bin/env python3
"""Authorize mirror releases against canonical source and CI provenance."""

import argparse
import base64
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
SOURCE_LABEL_RE = re.compile(r"^GitOrigin-RevId: ([0-9a-f]{40})$", re.MULTILINE)
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ALWAYS_SUCCESS_CHECKS = {
    "Detect changed areas",
    "Automation authority guards",
    "CI gate",
}


class ProvenanceError(RuntimeError):
    pass


def run_git(repo, *args):
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ProvenanceError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def parse_source_revision(message):
    matches = SOURCE_LABEL_RE.findall(message)
    if len(matches) != 1:
        raise ProvenanceError(
            f"tag commit must contain exactly one GitOrigin-RevId trailer, found {len(matches)}"
        )
    return matches[0]


def validate_tag_state(
    ref, event_sha, event, tag_commit, event_commit, after_commit, main_commit
):
    if not ref.startswith("refs/tags/"):
        raise ProvenanceError("release event is not a tag push")
    tag = ref.removeprefix("refs/tags/")
    if not TAG_RE.fullmatch(tag):
        raise ProvenanceError(f"release tag is not strict semver: {tag!r}")
    if not SHA_RE.fullmatch(event_sha):
        raise ProvenanceError("GITHUB_SHA is not a full commit SHA")
    if not event.get("created") or event.get("deleted") or event.get("forced"):
        raise ProvenanceError("release tags must be newly created and never moved or forced")
    if event.get("before") != "0" * 40:
        raise ProvenanceError("release tag update is not a new ref")
    if event.get("ref") != ref:
        raise ProvenanceError("event ref does not match GITHUB_REF")
    if after_commit != event_commit:
        raise ProvenanceError("push event after SHA does not peel to GITHUB_SHA")
    if tag_commit != event_commit:
        raise ProvenanceError("event SHA does not peel to the tagged commit")
    if tag_commit != main_commit:
        raise ProvenanceError("tagged commit is not exactly the current mirror main commit")
    return tag


def parse_required_checks(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProvenanceError(f"canonical required-check list is unreadable: {error}")
    checks = data.get("required_checks") if isinstance(data, dict) else None
    if not isinstance(checks, list) or not all(isinstance(name, str) and name for name in checks):
        raise ProvenanceError("canonical required-check list is absent or malformed")
    if not checks:
        raise ProvenanceError("canonical required-check list is absent")
    duplicates = sorted({name for name in checks if checks.count(name) > 1})
    if duplicates:
        raise ProvenanceError(f"canonical required-check list has duplicates: {duplicates}")
    return checks


def select_workflow_run(runs, source_sha):
    matching = [
        run
        for run in runs
        if run.get("head_sha") == source_sha
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and run.get("path") == ".github/workflows/ci.yml"
    ]
    if len(matching) != 1:
        raise ProvenanceError(
            f"canonical source must have exactly one main push CI run, found {len(matching)}"
        )
    run = matching[0]
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ProvenanceError("canonical source CI run is not currently successful")
    return run


def verify_required_checks(required, check_runs, workflow_run_id):
    marker = f"/actions/runs/{workflow_run_id}/"
    workflow_checks = [run for run in check_runs if marker in (run.get("details_url") or "")]
    names = [run.get("name") for run in workflow_checks]
    if len(names) != len(set(names)):
        raise ProvenanceError("canonical CI check set contains duplicate names")
    missing = [name for name in required if name not in names]
    unexpected = [name for name in names if name not in required]
    if missing or unexpected:
        raise ProvenanceError(
            f"canonical CI check set differs: missing={missing}, unexpected={unexpected}"
        )
    for name in required:
        matching = [run for run in workflow_checks if run.get("name") == name]
        if len(matching) != 1:
            raise ProvenanceError(
                f"required check {name!r} must appear exactly once, found {len(matching)}"
            )
        conclusion = matching[0].get("conclusion")
        allowed = {"success"} if name in ALWAYS_SUCCESS_CHECKS else {"success", "skipped"}
        if matching[0].get("status") != "completed" or conclusion not in allowed:
            raise ProvenanceError(f"required check {name!r} is not successful")


def load_components(path):
    components = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(components, dict) or not components:
        raise ProvenanceError("component map is empty or malformed")
    return components


def normalize_mode(path):
    if path.is_symlink():
        return "120000"
    return "100755" if path.stat().st_mode & stat.S_IXUSR else "100644"


def source_entry(path):
    if path.is_symlink():
        return normalize_mode(path), os.readlink(path).encode("utf-8")
    return normalize_mode(path), path.read_bytes()


def extract_workspace_preamble(copybara_config):
    text = Path(copybara_config).read_text(encoding="utf-8")
    match = re.search(r'WORKSPACE_PREAMBLE = """(.*?)"""', text, re.DOTALL)
    if not match:
        raise ProvenanceError("Copybara workspace preamble is absent")
    return match.group(1)


def expected_export_tree(source_root, component, components):
    helper_path = source_root / "tools/package-export-smoke.py"
    if not helper_path.is_file():
        raise ProvenanceError("canonical package export helper is absent")
    spec = importlib.util.spec_from_file_location("canonical_package_export", helper_path)
    if spec is None or spec.loader is None:
        raise ProvenanceError("canonical package export helper cannot be loaded")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    try:
        return helper.expected_export_tree(source_root, component, components)
    except (helper.ExportError, OSError, ValueError, UnicodeDecodeError) as error:
        raise ProvenanceError(f"canonical export transformation failed: {error}") from error


def select_native_run(runs, source_sha):
    matching = [
        run
        for run in runs
        if run.get("display_title") == f"Native artifacts for {source_sha}"
        and run.get("head_sha") == source_sha
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and run.get("path") == ".github/workflows/native-artifacts.yml"
    ]
    if len(matching) != 1:
        raise ProvenanceError(
            f"canonical source must have exactly one native artifact run, found {len(matching)}"
        )
    if any(not isinstance(run.get("id"), int) or run["id"] < 1 for run in matching):
        raise ProvenanceError("canonical native artifact run ID is invalid")
    run = matching[0]
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ProvenanceError("canonical native artifact run is not successful")
    if not isinstance(run.get("run_attempt"), int) or run["run_attempt"] < 1:
        raise ProvenanceError("canonical native artifact run attempt is invalid")
    return run


def git_tree(repo, commit):
    records = run_git(repo, "ls-tree", "-rz", "-r", commit).split(b"\0")
    tree = {}
    for record in records:
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
        if object_type != "blob":
            raise ProvenanceError(f"unsupported git tree object: {object_type}")
        path = raw_path.decode("utf-8")
        tree[path] = mode, run_git(repo, "cat-file", "blob", object_id)
    return tree


def compare_trees(expected, actual):
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    mismatched = sorted(
        path for path in set(expected) & set(actual) if expected[path] != actual[path]
    )
    if missing or extra or mismatched:
        details = []
        if missing:
            details.append(f"missing={missing[:10]}")
        if extra:
            details.append(f"extra={extra[:10]}")
        if mismatched:
            details.append(f"mismatched={mismatched[:10]}")
        raise ProvenanceError("mirror tree does not match canonical source: " + "; ".join(details))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token):
        if not token:
            raise ProvenanceError("SOURCE_TOKEN is required")
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "hop-release-provenance",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def request_json(self, path, query=None):
        url = "https://api.github.com" + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        request = urllib.request.Request(url, headers=self.headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except (urllib.error.HTTPError, urllib.error.URLError) as error:
            raise ProvenanceError(f"GitHub API request failed for {path}: {error}") from error

    def paged(self, path, key, query=None):
        values = []
        page = 1
        while True:
            parameters = dict(query or {})
            parameters.update({"per_page": 100, "page": page})
            payload = self.request_json(path, parameters)
            batch = payload.get(key, [])
            values.extend(batch)
            if len(batch) < 100:
                return values
            page += 1

    def download_source(self, repository, source_sha, destination):
        path = f"/repos/{repository}/tarball/{source_sha}"
        request = urllib.request.Request(
            "https://api.github.com" + path,
            headers=self.headers,
        )
        opener = urllib.request.build_opener(NoRedirect)
        try:
            opener.open(request, timeout=60)
            raise ProvenanceError("GitHub tarball endpoint did not redirect")
        except urllib.error.HTTPError as response:
            if response.code not in (301, 302, 307, 308):
                raise ProvenanceError(f"GitHub tarball request failed: HTTP {response.code}")
            location = response.headers.get("Location", "")
        parsed = urllib.parse.urlparse(location)
        if parsed.scheme != "https" or parsed.hostname != "codeload.github.com":
            raise ProvenanceError("GitHub tarball redirect used an unexpected host")
        archive = destination / "source.tar.gz"
        clean_request = urllib.request.Request(location, headers=self.headers)
        try:
            with urllib.request.urlopen(clean_request, timeout=120) as response, archive.open("wb") as output:
                shutil.copyfileobj(response, output)
        except (urllib.error.HTTPError, urllib.error.URLError) as error:
            raise ProvenanceError(f"canonical source download failed: {error}") from error
        extract_archive(archive, destination / "source")
        return destination / "source"


def extract_archive(archive, destination):
    destination.mkdir()
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        roots = {PurePosixPath(member.name).parts[0] for member in members if member.name}
        if len(roots) != 1:
            raise ProvenanceError("canonical source archive has an unexpected root")
        for member in members:
            parts = PurePosixPath(member.name).parts[1:]
            if not parts:
                continue
            if any(part in ("", ".", "..") for part in parts):
                raise ProvenanceError("canonical source archive contains an unsafe path")
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                link = PurePosixPath(member.linkname)
                resolved = PurePosixPath(*parts[:-1], link)
                if link.is_absolute() or ".." in resolved.parts:
                    raise ProvenanceError("canonical source archive contains an unsafe symlink")
                target.symlink_to(member.linkname)
                continue
            if not member.isfile():
                raise ProvenanceError("canonical source archive contains an unsupported entry")
            extracted = source.extractfile(member)
            if extracted is None:
                raise ProvenanceError("canonical source archive entry could not be read")
            with target.open("wb") as output:
                shutil.copyfileobj(extracted, output)
            target.chmod(member.mode & 0o777)


def api_repo(repository):
    if not REPOSITORY_RE.fullmatch(repository):
        raise ProvenanceError(f"invalid repository name: {repository!r}")
    return "/repos/" + repository


def verify(args):
    repo = Path(args.repository).resolve()
    components_path = repo / ".github/components.json"
    components = load_components(components_path)
    expected_mirror = f"hopmesh/{args.component}"
    if os.environ.get("GITHUB_REPOSITORY") != expected_mirror:
        raise ProvenanceError(f"workflow must run only in {expected_mirror}")

    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    ref = os.environ.get("GITHUB_REF", "")
    event_sha = os.environ.get("GITHUB_SHA", "")
    after_sha = event.get("after", "")
    if not SHA_RE.fullmatch(after_sha):
        raise ProvenanceError("push event after value is not a full SHA")
    tag_commit = run_git(repo, "rev-parse", f"{ref}^{{commit}}").decode().strip()
    event_commit = run_git(repo, "rev-parse", f"{event_sha}^{{commit}}").decode().strip()
    after_commit = run_git(repo, "rev-parse", f"{after_sha}^{{commit}}").decode().strip()
    run_git(repo, "fetch", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main")
    main_commit = run_git(repo, "rev-parse", "refs/remotes/origin/main^{commit}").decode().strip()
    tag = validate_tag_state(
        ref, event_sha, event, tag_commit, event_commit, after_commit, main_commit
    )

    message = run_git(repo, "show", "-s", "--format=%B", tag_commit).decode("utf-8")
    source_sha = parse_source_revision(message)
    source_repository = args.source_repository
    base = api_repo(source_repository)
    github = GitHub(os.environ.get("SOURCE_TOKEN", ""))
    main_ref = github.request_json(base + "/git/ref/heads/main")
    source_main = main_ref.get("object", {}).get("sha", "")
    if not SHA_RE.fullmatch(source_main):
        raise ProvenanceError("canonical main did not resolve to a commit SHA")
    comparison = github.request_json(base + f"/compare/{source_sha}...{source_main}")
    if comparison.get("status") not in ("ahead", "identical"):
        raise ProvenanceError("source metadata is not reachable from canonical main")

    with tempfile.TemporaryDirectory(prefix="hop-release-source-") as temporary:
        source_root = github.download_source(source_repository, source_sha, Path(temporary))
        expected = expected_export_tree(source_root, args.component, components)
        actual = git_tree(repo, tag_commit)
        compare_trees(expected, actual)
        required = parse_required_checks(source_root / "tools/required-checks.json")

    runs_payload = github.request_json(
        base + "/actions/workflows/ci.yml/runs",
        {"head_sha": source_sha, "branch": "main", "event": "push", "per_page": 100},
    )
    workflow_run = select_workflow_run(runs_payload.get("workflow_runs", []), source_sha)
    checks = github.paged(base + f"/commits/{source_sha}/check-runs", "check_runs")
    verify_required_checks(required, checks, workflow_run["id"])
    native_run_id = ""
    native_run_attempt = ""
    if args.require_native_artifacts:
        native_runs = github.paged(
            base + "/actions/workflows/native-artifacts.yml/runs",
            "workflow_runs",
            {"branch": "main", "event": "push", "head_sha": source_sha},
        )
        native_run = select_native_run(native_runs, source_sha)
        native_run_id = str(native_run["id"])
        native_run_attempt = str(native_run["run_attempt"])
    if args.github_output:
        output = Path(args.github_output)
        with output.open("a", encoding="utf-8") as destination:
            destination.write(f"source_sha={source_sha}\n")
            destination.write(f"source_ci_run_id={workflow_run['id']}\n")
            destination.write(f"version={tag.removeprefix('v')}\n")
            if native_run_id:
                destination.write(f"native_run_id={native_run_id}\n")
                destination.write(f"native_run_attempt={native_run_attempt}\n")
    detail = f" mirror={tag_commit} source={source_sha} ci_run={workflow_run['id']}"
    if native_run_id:
        detail += f" native_run={native_run_id}/{native_run_attempt}"
    print("release provenance verified:" + detail)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--component", required=True)
    parser.add_argument("--source-repository", default="hopmesh/monorepo")
    parser.add_argument("--repository", default=".")
    parser.add_argument("--require-native-artifacts", action="store_true")
    parser.add_argument("--github-output")
    args = parser.parse_args()
    try:
        verify(args)
    except (ProvenanceError, OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"release provenance rejected: {error}") from error


if __name__ == "__main__":
    main()
