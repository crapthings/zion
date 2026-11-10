#!/usr/bin/env python3
"""Build and sign the native macOS app with its Rust core and privileged helper."""

import hashlib
import os
import pathlib
import plistlib
import shutil
import subprocess


def run(arguments, root):
    """Run a required build step and stop packaging immediately on failure."""
    subprocess.run(arguments, cwd=root, check=True)


def assemble(root, swift_directory):
    """Copy release binaries and metadata into a fresh app bundle."""
    app = root / "target/macos/Zion.app"
    if app.exists():
        shutil.rmtree(app)
    contents = app / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    (contents / "Helpers").mkdir()
    (contents / "Library/HelperTools").mkdir(parents=True)
    (contents / "Library/LaunchDaemons").mkdir()
    shutil.copy2(swift_directory / "ZionHelper", contents / "Library/HelperTools/zion-helper")
    daemon = {
        "Label": "dev.zion.helper",
        "BundleProgram": "Contents/Library/HelperTools/zion-helper",
        "MachServices": {"dev.zion.helper": True},
    }
    with (contents / "Library/LaunchDaemons/dev.zion.helper.plist").open("wb") as output:
        plistlib.dump(daemon, output)
    shutil.copy2(swift_directory / "ZionMac", contents / "MacOS/Zion")
    shutil.copy2(root / "target/release/zion", contents / "Helpers/zion-core")
    metadata = {
        "CFBundleDevelopmentRegion": "zh_CN",
        "CFBundleDisplayName": "Zion",
        "CFBundleName": "Zion",
        "CFBundleExecutable": "Zion",
        "CFBundleIdentifier": "dev.zion.client",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "0.1.0",
        "CFBundleVersion": "1",
        "LSMinimumSystemVersion": "14.0",
        "NSHighResolutionCapable": True,
        "NSPrincipalClass": "NSApplication",
    }
    with (contents / "Info.plist").open("wb") as output:
        plistlib.dump(metadata, output)
    return app


def archive_digest(path):
    """Fingerprint the external Rust archive that SwiftPM does not track as a target input."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    """Compile the core and native helpers, then verify the signed application bundle."""
    root = pathlib.Path(__file__).resolve().parent.parent
    os.environ["MACOSX_DEPLOYMENT_TARGET"] = "14.0"
    run(["cargo", "build", "--locked", "--release", "--features", "tun-device"], root)
    archive = root / "target/release/libzion.a"
    os.environ["ZION_PACKET_LIBRARY"] = str(archive)
    fingerprint = archive_digest(archive)
    stamp = root / "target/macos-native.sha256"
    if not stamp.exists() or stamp.read_text().strip() != fingerprint:
        print("Rust archive changed; rebuilding Swift targets.", flush=True)
        run(["swift", "package", "--package-path", "macos", "clean"], root)
    run(["swift", "build", "--package-path", "macos", "-c", "release"], root)
    location = subprocess.check_output(
        ["swift", "build", "--package-path", "macos", "-c", "release", "--show-bin-path"],
        cwd=root, text=True,
    ).strip()
    app = assemble(root, pathlib.Path(location))
    identity = os.environ.get("ZION_CODESIGN_IDENTITY", "-")
    signing = ["codesign", "--force", "--sign", identity]
    if identity != "-":
        signing += ["--options", "runtime", "--timestamp"]
    run(signing + [str(app / "Contents/Helpers/zion-core")], root)
    run(signing + ["--identifier", "dev.zion.helper", str(app / "Contents/Library/HelperTools/zion-helper")], root)
    run(signing + [str(app)], root)
    run(["codesign", "--verify", "--deep", "--strict", str(app)], root)
    stamp.write_text(fingerprint + "\n")
    print(app)


if __name__ == "__main__":
    main()
