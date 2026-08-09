"""Focused tests for the independent MCPB archive and input verifier."""

from __future__ import annotations

import json
import shutil
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path


MODULE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = MODULE_DIR.parents[1]
sys.path.insert(0, str(MODULE_DIR))

import verify_bundle as verifier  # noqa: E402


# Builds the smallest PE32+ byte sequence accepted by the packaging contract.
def make_test_pe(machine: int = 0x8664) -> bytes:
    """Return a synthetic executable with one section and an AMD64 PE header."""

    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, machine, 1)
    struct.pack_into("<HH", data, 0x94, 0xF0, 0x0002)
    struct.pack_into("<H", data, 0x98, 0x020B)
    return bytes(data)


# Creates a valid staged bundle for archive-verifier tests.
def make_stage(root: Path, version: str = "1.2.3") -> Path:
    """Populate one temporary directory with the exact four bundle payloads."""

    stage = root / "stage"
    (stage / "server").mkdir(parents=True)
    manifest = json.loads((MODULE_DIR / "staging" / "manifest.json").read_text())
    manifest["version"] = version
    (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    shutil.copyfile(MODULE_DIR / "staging" / "README.md", stage / "README.md")
    shutil.copyfile(REPO_ROOT / "LICENSE", stage / "LICENSE")
    (stage / "server" / "frameshift-mcp.exe").write_bytes(make_test_pe())
    return stage


# Writes a ZIP from staged files with the same stable metadata required from MCPB.
def make_archive(path: Path, stage: Path, names: list[str]) -> None:
    """Create a controlled ZIP fixture for positive and hostile inventory tests."""

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            info = zipfile.ZipInfo(name, verifier.EXPECTED_ARCHIVE_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            source_name = name if name in verifier.EXPECTED_BUNDLE_FILES else "manifest.json"
            payload = stage.joinpath(*Path(source_name).parts).read_bytes()
            archive.writestr(info, payload)


# Exercises SemVer, PE, staging inventory, and hostile ZIP edge cases.
class VerifyBundleTests(unittest.TestCase):
    """Proves the independent verifier rejects ambiguous MCPB inputs."""

    # Accepts stable, prerelease, and build-metadata SemVer strings.
    def test_semver_accepts_release_variants(self) -> None:
        """Allow the release versions supported by semantic version tags."""

        for version in ("0.1.0", "1.2.3-beta.1", "2.0.0+build.7", "3.4.5-rc.1+x"):
            verifier.validate_semver(version)

    # Rejects malformed or numerically zero-padded release versions.
    def test_semver_rejects_invalid_versions(self) -> None:
        """Reject versions that would produce ambiguous manifests or filenames."""

        for version in ("v1.2.3", "1.2", "01.2.3", "1.2.3-01", "1.2.3+"):
            with self.subTest(version=version):
                with self.assertRaises(verifier.BundleVerificationError):
                    verifier.validate_semver(version)

    # Rejects a valid PE container compiled for a non-AMD64 architecture.
    def test_binary_rejects_wrong_machine(self) -> None:
        """Prove an .exe suffix cannot bypass the target-platform check."""

        with self.assertRaisesRegex(
            verifier.BundleVerificationError, "not an x86_64 Windows executable"
        ):
            verifier.validate_windows_binary(make_test_pe(machine=0x014C), "fixture")

    # Rejects extra files in the reviewed, checked-in staging source.
    def test_source_inventory_rejects_unexpected_file(self) -> None:
        """Prove the source allowlist fails closed before temporary staging."""

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            shutil.copyfile(MODULE_DIR / "staging" / "manifest.json", source / "manifest.json")
            shutil.copyfile(MODULE_DIR / "staging" / "README.md", source / "README.md")
            (source / "surprise.txt").write_text("unexpected\n")
            with self.assertRaisesRegex(verifier.BundleVerificationError, "inventory mismatch"):
                verifier.validate_source_directory(source)

    # Accepts an independently assembled archive that meets the complete contract.
    def test_archive_accepts_exact_inventory(self) -> None:
        """Check exact content, fixed timestamps, safe paths, and staged-byte equality."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = make_stage(root)
            archive = root / "frameshift-windows-1.2.3.mcpb"
            make_archive(archive, stage, sorted(verifier.EXPECTED_BUNDLE_FILES))
            verifier.validate_archive(archive, stage, "1.2.3")

    # Rejects duplicate names before a set-based inventory comparison can hide them.
    def test_archive_rejects_duplicate_entry(self) -> None:
        """Prove two manifest.json entries cannot collapse into one logical file."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = make_stage(root)
            archive = root / "duplicate.mcpb"
            names = sorted(verifier.EXPECTED_BUNDLE_FILES) + ["manifest.json"]
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                make_archive(archive, stage, names)
            with self.assertRaisesRegex(verifier.BundleVerificationError, "duplicate entry"):
                verifier.validate_archive(archive, stage, "1.2.3")

    # Rejects an archive that omits any file from the exact bundle contract.
    def test_archive_rejects_missing_entry(self) -> None:
        """Prove a superficially valid ZIP cannot omit the native server binary."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = make_stage(root)
            archive = root / "missing.mcpb"
            names = sorted(
                verifier.EXPECTED_BUNDLE_FILES - {"server/frameshift-mcp.exe"}
            )
            make_archive(archive, stage, names)
            with self.assertRaisesRegex(verifier.BundleVerificationError, "inventory"):
                verifier.validate_archive(archive, stage, "1.2.3")

    # Rejects parent traversal before opening or joining an archive path.
    def test_archive_rejects_parent_traversal(self) -> None:
        """Prove a ZIP entry cannot escape the installed bundle root."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = make_stage(root)
            archive = root / "traversal.mcpb"
            make_archive(archive, stage, ["../manifest.json"])
            with self.assertRaisesRegex(verifier.BundleVerificationError, "unsafe component"):
                verifier.validate_archive(archive, stage, "1.2.3")


if __name__ == "__main__":
    unittest.main()
