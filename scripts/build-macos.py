#!/usr/bin/env python3
"""Build and package the native macOS app with its owned Rust proxy helper."""

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


def main():
    """Compile both components and verify a locally usable ad hoc signed bundle."""
    root = pathlib.Path(__file__).resolve().parent.parent
    os.environ["MACOSX_DEPLOYMENT_TARGET"] = "14.0"
    run(["cargo", "build", "--locked", "--release", "--features", "packet-tunnel"], root)
    os.environ["ZION_PACKET_LIBRARY"] = str(root / "target/release/libzion.a")
    run(["swift", "build", "--package-path", "macos", "-c", "release"], root)
    location = subprocess.check_output(
        ["swift", "build", "--package-path", "macos", "-c", "release", "--show-bin-path"],
        cwd=root, text=True,
    ).strip()
    app = assemble(root, pathlib.Path(location))
    run(["codesign", "--force", "--sign", "-", str(app / "Contents/Helpers/zion-core")], root)
    run(["codesign", "--force", "--sign", "-", str(app)], root)
    run(["codesign", "--verify", "--deep", "--strict", str(app)], root)
    print(app)


if __name__ == "__main__":
    main()
