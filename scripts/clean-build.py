#!/usr/bin/env python3
"""Remove generated build caches, preserving the packaged app unless --all is requested."""

import argparse
import pathlib
import shutil


# Build cleanup is confined to paths owned by this checkout.
ROOT = pathlib.Path(__file__).resolve().parent.parent


def remove(path):
    """Delete one generated entry without traversing directory symlinks."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def main():
    """Clean Rust and Swift products while leaving source, configuration, and credentials intact."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="also remove target/macos and the packaged app")
    args = parser.parse_args()
    target = ROOT / "target"
    if target.is_symlink():
        raise RuntimeError("refusing to clean a symlinked target directory")
    if target.exists():
        for entry in target.iterdir():
            if args.all or entry.name != "macos":
                remove(entry)
    remove(ROOT / "macos/.build")
    remove(ROOT / "scripts/__pycache__")
    print("Build caches removed." if not args.all else "Build caches and packaged app removed.")


# Run cleanup only when explicitly invoked from the command line.
if __name__ == "__main__":
    main()
