"""Regenerate MANIFEST.sha256 for the tracked DICOM payload."""

from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    files = sorted(ROOT.glob("*/**/*.dcm"))
    if not files:
        raise SystemExit("No DICOM files found; refusing to write an empty manifest")
    lines = [f"{sha256(path)}  {path.relative_to(ROOT).as_posix()}" for path in files]
    MANIFEST.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"Wrote {len(lines)} checksums to {MANIFEST.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
