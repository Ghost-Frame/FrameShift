#!/usr/bin/env python3
"""Independently verifies FrameShift MCPB inputs and packed ZIP artifacts."""

from __future__ import annotations

import argparse
import json
import os
import posixpath
import re
import stat
import struct
import sys
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath
from typing import NoReturn


MCPB_VERSION = "2.1.2"
TEMPLATE_VERSION = "0.0.0"
EXPECTED_SOURCE_FILES = frozenset({"README.md", "manifest.json"})
EXPECTED_SOURCE_DIRECTORIES: frozenset[str] = frozenset()
EXPECTED_BUNDLE_FILES = frozenset(
    {"LICENSE", "README.md", "manifest.json", "server/frameshift-mcp.exe"}
)
EXPECTED_BUNDLE_DIRECTORIES = frozenset({"server"})
EXPECTED_ARCHIVE_TIMESTAMP = (2000, 1, 1, 0, 0, 0)
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_UNPACKED_BYTES = 256 * 1024 * 1024
SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


# Represents any contract violation found before an MCPB artifact can ship.
class BundleVerificationError(Exception):
    """Reports one fail-closed MCPB verification error."""


# Raises a consistently typed verification failure with a focused message.
def reject(message: str) -> NoReturn:
    """Stop verification because one artifact contract was violated."""

    raise BundleVerificationError(message)


# Accepts only complete SemVer 2.0.0 strings without leading-zero numeric fields.
def validate_semver(version: str) -> None:
    """Validate one release version against the SemVer 2.0.0 grammar."""

    if not SEMVER_PATTERN.fullmatch(version):
        reject(f"version is not valid SemVer: {version!r}")


# Collects regular files and directories without following any symbolic link.
def collect_inventory(root: Path, label: str) -> tuple[set[str], set[str]]:
    """Return normalized relative files and directories beneath one root."""

    if root.is_symlink() or not root.is_dir():
        reject(f"{label} is not a real directory: {root}")

    files: set[str] = set()
    directories: set[str] = set()
    pending = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: os.fsencode(item.name)):
                relative = f"{prefix}/{entry.name}" if prefix else entry.name
                if entry.is_symlink():
                    reject(f"{label} contains a symbolic link: {relative}")
                if entry.is_dir(follow_symlinks=False):
                    directories.add(relative)
                    pending.append((Path(entry.path), relative))
                elif entry.is_file(follow_symlinks=False):
                    files.add(relative)
                else:
                    reject(f"{label} contains a non-regular entry: {relative}")
    return files, directories


# Requires an inventory to match its allowlist with no ignored or extra entries.
def validate_inventory(
    root: Path,
    expected_files: frozenset[str],
    expected_directories: frozenset[str],
    label: str,
) -> None:
    """Compare one directory tree with its exact file and directory contract."""

    files, directories = collect_inventory(root, label)
    if files != expected_files:
        reject(
            f"{label} file inventory mismatch: expected {sorted(expected_files)}, "
            f"found {sorted(files)}"
        )
    if directories != expected_directories:
        reject(
            f"{label} directory inventory mismatch: "
            f"expected {sorted(expected_directories)}, found {sorted(directories)}"
        )


# Parses a JSON object while rejecting duplicate object keys at every depth.
def load_json_object(data: bytes, label: str) -> dict[str, object]:
    """Decode one UTF-8 JSON object and reject duplicate field names."""

    # Rejects duplicate keys before Python can collapse them into one value.
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                reject(f"{label} contains duplicate JSON field {key!r}")
            result[key] = value
        return result

    try:
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        reject(f"{label} is not valid UTF-8 JSON: {error}")
    if not isinstance(parsed, dict):
        reject(f"{label} must contain a JSON object")
    return parsed


# Enforces the product-specific subset of the validated MCPB manifest schema.
def validate_manifest(data: bytes, version: str, label: str) -> dict[str, object]:
    """Check fixed FrameShift identity, binary launch, and Windows compatibility."""

    validate_semver(version)
    manifest = load_json_object(data, label)
    if manifest.get("manifest_version") != "0.3":
        reject(f"{label} must use manifest_version 0.3")
    if manifest.get("name") != "frameshift":
        reject(f"{label} must use the stable machine name 'frameshift'")
    if manifest.get("version") != version:
        reject(f"{label} version does not equal {version!r}")

    expected_server = {
        "type": "binary",
        "entry_point": "server/frameshift-mcp",
        "mcp_config": {
            "command": "${__dirname}/server/frameshift-mcp",
            "args": [],
        },
    }
    if manifest.get("server") != expected_server:
        reject(f"{label} does not match the native binary launch contract")
    if manifest.get("compatibility") != {"platforms": ["win32"]}:
        reject(f"{label} must declare win32 as its only compatible platform")
    expected_privacy_policies = [
        "https://github.com/Ghost-Frame/FrameShift/wiki/Local-Data-and-Privacy"
    ]
    if manifest.get("privacy_policies") != expected_privacy_policies:
        reject(f"{label} must link the reviewed local-data and privacy policy")
    for forbidden_field in ("dependencies", "user_config"):
        if forbidden_field in manifest:
            reject(f"{label} must not declare {forbidden_field}")
    return manifest


# Requires an AMD64 PE32+ executable rather than trusting an .exe suffix.
def validate_windows_binary(data: bytes, label: str) -> None:
    """Check DOS, PE, machine, executable, section, and optional-header fields."""

    if len(data) < 0x40 or data[:2] != b"MZ":
        reject(f"{label} is missing the DOS MZ header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 26 > len(data):
        reject(f"{label} has an invalid PE header offset")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        reject(f"{label} is missing the PE signature")

    machine, sections = struct.unpack_from("<HH", data, pe_offset + 4)
    optional_size, characteristics = struct.unpack_from("<HH", data, pe_offset + 20)
    if machine != 0x8664:
        reject(f"{label} is not an x86_64 Windows executable")
    if sections == 0:
        reject(f"{label} has no PE sections")
    if characteristics & 0x0002 == 0:
        reject(f"{label} is not marked executable")
    if optional_size < 2 or pe_offset + 24 + optional_size > len(data):
        reject(f"{label} has an invalid PE optional header")
    if struct.unpack_from("<H", data, pe_offset + 24)[0] != 0x020B:
        reject(f"{label} is not a PE32+ executable")


# Validates a filesystem binary before the MCPB CLI can read or copy it.
def validate_binary_file(path: Path) -> None:
    """Reject absent, linked, misnamed, non-regular, or wrong-platform binaries."""

    if path.name != "frameshift-mcp.exe":
        reject(f"binary basename must be frameshift-mcp.exe, found {path.name!r}")
    if path.is_symlink() or not path.is_file():
        reject(f"binary is not a real regular file: {path}")
    validate_windows_binary(path.read_bytes(), str(path))


# Validates the checked-in source staging directory before copying any file.
def validate_source_directory(path: Path) -> None:
    """Require the two reviewed staging source files and no other entry."""

    validate_inventory(
        path,
        EXPECTED_SOURCE_FILES,
        EXPECTED_SOURCE_DIRECTORIES,
        "MCPB staging source",
    )
    validate_manifest(
        (path / "manifest.json").read_bytes(),
        TEMPLATE_VERSION,
        "staging manifest",
    )


# Renders the reviewed manifest template with exactly one caller-supplied version.
def render_manifest(template: Path, version: str, output: Path) -> None:
    """Write a canonical release manifest without accepting other substitutions."""

    validate_semver(version)
    manifest = validate_manifest(template.read_bytes(), TEMPLATE_VERSION, str(template))
    manifest["version"] = version
    rendered = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    validate_manifest(rendered, version, str(output))
    if output.exists() or output.is_symlink():
        reject(f"refusing to overwrite manifest output: {output}")
    output.write_bytes(rendered)


# Validates the completed temporary bundle tree before the official pack step.
def validate_stage_directory(path: Path, version: str) -> None:
    """Require the exact four payload files and validate their typed contents."""

    validate_inventory(
        path,
        EXPECTED_BUNDLE_FILES,
        EXPECTED_BUNDLE_DIRECTORIES,
        "MCPB stage",
    )
    validate_manifest((path / "manifest.json").read_bytes(), version, "staged manifest")
    validate_windows_binary(
        (path / "server" / "frameshift-mcp.exe").read_bytes(),
        "staged server/frameshift-mcp.exe",
    )


# Rejects paths that a ZIP extractor could reinterpret outside the bundle root.
def validate_archive_name(name: str) -> None:
    """Require one normalized relative POSIX archive path."""

    if not name or "\x00" in name or "\\" in name:
        reject(f"archive contains an invalid path: {name!r}")
    if unicodedata.normalize("NFC", name) != name:
        reject(f"archive path is not NFC-normalized: {name!r}")
    if name.startswith("/") or name.endswith("/"):
        reject(f"archive path is not a regular relative file: {name!r}")
    parts = PurePosixPath(name).parts
    if not parts or any(part in {"", ".", ".."} for part in name.split("/")):
        reject(f"archive path contains an unsafe component: {name!r}")
    if ":" in parts[0] or posixpath.normpath(name) != name:
        reject(f"archive path can escape or alias the bundle root: {name!r}")


# Rejects symbolic links, devices, and other non-regular Unix ZIP entry types.
def validate_archive_file_type(info: zipfile.ZipInfo) -> None:
    """Accept regular-file metadata from Unix or Windows MCPB packer output."""

    unix_mode = info.external_attr >> 16
    file_type = stat.S_IFMT(unix_mode)
    if file_type not in (0, stat.S_IFREG):
        reject(f"archive entry is not a regular file: {info.filename!r}")
    if info.is_dir():
        reject(f"archive contains an unexpected directory entry: {info.filename!r}")


# Independently validates ZIP inventory, metadata, content, and staged-byte equality.
def validate_archive(path: Path, stage: Path, version: str) -> None:
    """Verify the final MCPB without relying on the MCPB validator or packer."""

    validate_stage_directory(stage, version)
    if path.is_symlink() or not path.is_file():
        reject(f"MCPB output is not a real regular file: {path}")
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        reject(f"MCPB archive exceeds {MAX_ARCHIVE_BYTES} bytes")
    if not zipfile.is_zipfile(path):
        reject(f"MCPB output is not a ZIP archive: {path}")

    with zipfile.ZipFile(path, "r") as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        for name in names:
            validate_archive_name(name)
        if len(names) != len(set(names)):
            reject("archive contains duplicate entry names")
        normalized_names = [unicodedata.normalize("NFC", name).casefold() for name in names]
        if len(normalized_names) != len(set(normalized_names)):
            reject("archive contains case-folded or normalized duplicate paths")
        if names != sorted(EXPECTED_BUNDLE_FILES, key=os.fsencode):
            reject(
                f"archive inventory or order mismatch: expected "
                f"{sorted(EXPECTED_BUNDLE_FILES, key=os.fsencode)}, found {names}"
            )
        if sum(entry.file_size for entry in entries) > MAX_UNPACKED_BYTES:
            reject(f"MCPB contents exceed {MAX_UNPACKED_BYTES} bytes")

        contents: dict[str, bytes] = {}
        for entry in entries:
            validate_archive_file_type(entry)
            if entry.flag_bits & 0x1:
                reject(f"archive entry is encrypted: {entry.filename!r}")
            if entry.date_time != EXPECTED_ARCHIVE_TIMESTAMP:
                reject(
                    f"archive entry has nondeterministic timestamp "
                    f"{entry.date_time!r}: {entry.filename!r}"
                )
            try:
                payload = archive.read(entry)
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                reject(f"archive entry failed CRC or decompression checks: {error}")
            staged_payload = (stage / Path(*PurePosixPath(entry.filename).parts)).read_bytes()
            if payload != staged_payload:
                reject(f"archive entry differs from staged bytes: {entry.filename!r}")
            contents[entry.filename] = payload

    validate_manifest(contents["manifest.json"], version, "archived manifest")
    validate_windows_binary(
        contents["server/frameshift-mcp.exe"],
        "archived server/frameshift-mcp.exe",
    )


# Defines the small command-line surface used by packaging and focused tests.
def build_parser() -> argparse.ArgumentParser:
    """Build the verifier argument parser and its fail-closed subcommands."""

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    version_parser = subparsers.add_parser("version", help="validate one SemVer")
    version_parser.add_argument("version")

    source_parser = subparsers.add_parser("source", help="validate staging sources")
    source_parser.add_argument("path", type=Path)

    binary_parser = subparsers.add_parser("binary", help="validate a Windows binary")
    binary_parser.add_argument("path", type=Path)

    render_parser = subparsers.add_parser("render", help="render a versioned manifest")
    render_parser.add_argument("template", type=Path)
    render_parser.add_argument("version")
    render_parser.add_argument("output", type=Path)

    stage_parser = subparsers.add_parser("stage", help="validate a staged bundle")
    stage_parser.add_argument("path", type=Path)
    stage_parser.add_argument("version")

    archive_parser = subparsers.add_parser("archive", help="validate a packed MCPB")
    archive_parser.add_argument("path", type=Path)
    archive_parser.add_argument("stage", type=Path)
    archive_parser.add_argument("version")
    return parser


# Dispatches one verification command and converts contract violations to exit 1.
def main() -> int:
    """Run the selected verifier operation with concise diagnostic output."""

    args = build_parser().parse_args()
    try:
        if args.command == "version":
            validate_semver(args.version)
        elif args.command == "source":
            validate_source_directory(args.path)
        elif args.command == "binary":
            validate_binary_file(args.path)
        elif args.command == "render":
            render_manifest(args.template, args.version, args.output)
        elif args.command == "stage":
            validate_stage_directory(args.path, args.version)
        elif args.command == "archive":
            validate_archive(args.path, args.stage, args.version)
        else:
            reject(f"unsupported verifier command: {args.command!r}")
    except (BundleVerificationError, OSError) as error:
        print(f"MCPB verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
