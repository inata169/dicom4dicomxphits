"""Fail-closed privacy and integrity audit for this DICOM data repository."""

from __future__ import annotations

import argparse
import hashlib
from collections import Counter, defaultdict
from pathlib import Path
import sys

import pydicom


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"
GITHUB_HARD_LIMIT = 100 * 1024 * 1024

EXPECTED_IDENTITIES = {
    "PatientName": {"ANONYMOUS"},
    "PatientID": {"9000001", "9000002"},
    "PatientBirthDate": {"19000101"},
    "PatientSex": {"O"},
    "ReferringPhysicianName": {"ANONYMOUS_PHYSIC"},
    "InstitutionName": {"", "ANONYMOUS_INSTIT"},
    "StationName": {"", "ANON_STATION"},
    "OtherPatientIDs": {"", "MonacoPhantom"},
    "OtherPatientNames": {"", "30x30x30,Monaco"},
}

MUST_BE_EMPTY = {
    "AccessionNumber",
    "DeviceSerialNumber",
    "InstitutionAddress",
    "OperatorsName",
    "PatientAddress",
    "PatientTelephoneNumbers",
    "PerformingPhysicianName",
    "RequestingPhysician",
    "ResponsibleOrganization",
    "ResponsiblePerson",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dicom_files() -> list[Path]:
    return sorted(ROOT.glob("*/**/*.dcm"))


def verify_checksums(files: list[Path], errors: list[str]) -> None:
    if not MANIFEST.is_file():
        errors.append("MANIFEST.sha256 is missing")
        return
    expected: dict[str, str] = {}
    for number, line in enumerate(MANIFEST.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            digest, relative = line.split("  ", 1)
        except ValueError:
            errors.append(f"MANIFEST.sha256:{number}: invalid line")
            continue
        expected[relative] = digest
    actual_paths = {path.relative_to(ROOT).as_posix() for path in files}
    if set(expected) != actual_paths:
        missing = sorted(actual_paths - set(expected))
        stale = sorted(set(expected) - actual_paths)
        if missing:
            errors.append(f"checksum entries missing for: {', '.join(missing[:5])}")
        if stale:
            errors.append(f"stale checksum entries for: {', '.join(stale[:5])}")
    for relative in sorted(actual_paths & set(expected)):
        actual = sha256(ROOT / relative)
        if actual != expected[relative]:
            errors.append(f"checksum mismatch: {relative}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-checksums", action="store_true")
    args = parser.parse_args()

    files = dicom_files()
    errors: list[str] = []
    warnings: list[str] = []
    modalities: Counter[str] = Counter()
    cases: dict[str, list[tuple[Path, object]]] = defaultdict(list)
    sop_paths: dict[str, list[Path]] = defaultdict(list)
    missing_burned_in_annotation = 0

    if not files:
        errors.append("no DICOM files found")

    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        if path.stat().st_size >= GITHUB_HARD_LIMIT:
            errors.append(f"file is at or above 100 MiB: {relative}")
        try:
            dataset = pydicom.dcmread(path, stop_before_pixels=True)
        except Exception as exc:
            errors.append(f"cannot parse {relative}: {exc}")
            continue

        modality = str(getattr(dataset, "Modality", ""))
        modalities[modality] += 1
        cases[path.relative_to(ROOT).parts[0]].append((path, dataset))
        sop_uid = str(getattr(dataset, "SOPInstanceUID", ""))
        if not sop_uid:
            errors.append(f"missing SOPInstanceUID: {relative}")
        else:
            sop_paths[sop_uid].append(path)

        for keyword, allowed in EXPECTED_IDENTITIES.items():
            value = str(getattr(dataset, keyword, ""))
            if value not in allowed:
                errors.append(f"unexpected {keyword}={value!r}: {relative}")
        for keyword in MUST_BE_EMPTY:
            value = str(getattr(dataset, keyword, ""))
            if value:
                errors.append(f"non-empty {keyword}: {relative}")
        burned_in = str(getattr(dataset, "BurnedInAnnotation", "")).upper()
        if not burned_in:
            missing_burned_in_annotation += 1
        elif burned_in != "NO":
            errors.append(f"BurnedInAnnotation is not NO: {relative}")

        for element in dataset.iterall():
            if element.tag.is_private:
                errors.append(f"private DICOM element {element.tag}: {relative}")
            if 0x6000 <= element.tag.group <= 0x60FF:
                errors.append(f"overlay element {element.tag}: {relative}")
            if element.VR == "PN" and str(element.value) not in {
                "",
                "ANONYMOUS",
                "ANONYMOUS_PHYSIC",
                "30x30x30,Monaco",
            }:
                errors.append(f"unexpected person-name value in {element.tag}: {relative}")
            if (
                element.VR == "UI"
                and element.keyword != "InstanceCreatorUID"
                and str(element.value).startswith("2.16.840.1.114337.")
            ):
                errors.append(f"legacy source UID remains in {element.keyword}: {relative}")

    if modalities != Counter({"CT": 426, "RTDOSE": 20, "RTPLAN": 6}):
        errors.append(f"unexpected modality inventory: {dict(modalities)}")

    for case, records in sorted(cases.items()):
        studies = {str(getattr(ds, "StudyInstanceUID", "")) for _, ds in records}
        frames = {str(getattr(ds, "FrameOfReferenceUID", "")) for _, ds in records}
        plans = {str(ds.SOPInstanceUID) for _, ds in records if str(ds.Modality) == "RTPLAN"}
        if len(studies) != 1:
            errors.append(f"{case}: expected one StudyInstanceUID, found {len(studies)}")
        if len(frames) != 1:
            errors.append(f"{case}: expected one FrameOfReferenceUID, found {len(frames)}")
        if len(plans) != 1:
            errors.append(f"{case}: expected one RT Plan, found {len(plans)}")
        for path, dataset in records:
            if str(dataset.Modality) != "RTDOSE":
                continue
            references = {
                str(item.ReferencedSOPInstanceUID)
                for item in getattr(dataset, "ReferencedRTPlanSequence", [])
            }
            if references != plans:
                errors.append(
                    f"{path.relative_to(ROOT).as_posix()}: RT Plan reference does not resolve"
                )

    duplicates = {uid: paths for uid, paths in sop_paths.items() if len(paths) > 1}
    for uid, paths in sorted(duplicates.items()):
        shown = ", ".join(path.relative_to(ROOT).as_posix() for path in paths)
        errors.append(f"duplicate SOPInstanceUID {uid}: {shown}")

    if missing_burned_in_annotation:
        warnings.append(
            f"BurnedInAnnotation is absent from {missing_burned_in_annotation} files; "
            "representative pixels require visual review"
        )

    if args.check_checksums:
        verify_checksums(files, errors)

    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)

    total = sum(path.stat().st_size for path in files)
    print(
        f"Audited {len(files)} files ({total / 1024 / 1024:.2f} MiB): "
        f"{dict(sorted(modalities.items()))}"
    )
    print(f"Cases: {len(cases)}; warnings: {len(warnings)}; errors: {len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
