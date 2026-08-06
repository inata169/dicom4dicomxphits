"""Fail-closed privacy and integrity audit for this DICOM data repository."""

from __future__ import annotations

import argparse
import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path
import sys
import warnings

import pydicom
from pydicom.multival import MultiValue
from pydicom.uid import PYDICOM_ROOT_UID


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"
GITHUB_HARD_LIMIT = 100 * 1024 * 1024

HUMAN_READABLE_VRS = {
    "AE",
    "AS",
    "CS",
    "DA",
    "DS",
    "DT",
    "IS",
    "LO",
    "LT",
    "PN",
    "SH",
    "ST",
    "TM",
    "UC",
    "UI",
    "UR",
    "UT",
}
STRUCTURED_TEXT_VRS = {"AS", "DA", "DS", "DT", "IS", "TM", "UI"}
VENDOR_INSTANCE_CREATOR_UID = "2.16.840.1.114337"

AS_PATTERN = re.compile(r"^\d{3}[DWMY]$")
DA_PATTERN = re.compile(r"^\d{8}$")
DS_PATTERN = re.compile(r"^[+-]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:[Ee][+-]?\d+)?$")
DT_PATTERN = re.compile(
    r"^\d{4}(?:\d{2}(?:\d{2}(?:\d{2}(?:\d{2}(?:\d{2}"
    r"(?:\.\d{1,6})?)?)?)?)?)?(?:[+-]\d{4})?$"
)
IS_PATTERN = re.compile(r"^[+-]?\d+$")
TM_PATTERN = re.compile(r"^\d{2}(?:\d{2}(?:\d{2}(?:\.\d{1,6})?)?)?$")
UI_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")

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

# Full SHA-256 values keep reviewed fixture strings out of source and CI output.
# The map is deliberately tag-specific: a value approved for a beam label must
# not become acceptable in an institution or operator field. Empty values are
# safe for every textual tag and are handled separately.
ALLOWED_TEXT_FINGERPRINTS = {
    "ApprovalStatus": frozenset({"65f477475de2fd67266d3ac15353d53df2ecd52c65d53500d1982f3521fd5bd8"}),
    "BeamDescription": frozenset(
        """401ca379d8c6538e853d8402edd44295405a76d7fb3ab4d3a33cc493644287f1
        44a6552bf6173c9723e6df729deac9ae5d392b871309aa68140a8c00b9bbea1a
        46ad7d19d67273b16b327aad2f97112c13a6cbd91dfdc872dcaf88e6e06e9ec2
        4be1443c6383b92c8d88f3fc8de9c993b0d5ee8dcf1e5f1f8047b3173ee65881
        665bb9f1a9bdfa9a7232bfd5bb72c004f002cb04d30f72fc422a1c9709131e2b
        708c715405189bdef5636a3f163d01430f1e28c50a8c493b16011b91aa00ac5a
        773c6ae8b6645da243b0924ab5a3504394218d2961b98cd7eae17cb9c6c007dd
        773e806322cada6d04c4ca88502d9f5e11fcc94e048f7fe7fb57bd2b12cb496b
        84cb173569b203a791efe9a605d0a4cc6fbc79c9a98e385e24547961a98a92df
        9562d5b9c5c4ac4c3f3010947850a7929e063ac0d1a7bcb019d94c29690c64fc
        970badf49326e161cfab27dfe6621cbf510ac4ecf0684428c8c2ed095d367721
        9f034ac3ea44704c6bd696b56515e31684bd6f21c85f5eb13b2d5cfa76afee4b
        a4e3c33515cf871ec73f66f3d1a384d0791a7ed6816e2d260e0a4e0b35e63fca
        b335821ddeeb08997230125583b3c0f8f413ac1006ebcf1c394ec9d51dfada6b
        dbacf76b7d6731a74b3042c9fe1ff2c68b1c42fed46d0fcb59369230c13a4e92
        e2b2a0e4817dd81ba8092e3f7f2550d0bb51ca4639d6ebbec939c975bac77306
        ff9323296d4dd7f66c33f55a397c4630ac98664ac21adcb66052bd72e9a56643""".split()
    ),
    "BeamLimitingDeviceRotationDirection": frozenset({"c627c09c14e58e44bc51622dac392958ec88244e414b508020634f53cfcd1e69"}),
    "BeamName": frozenset(
        """4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a
        4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce
        4fc82b26aecb47d2868c4efbe3581732a3e7cbcc6c2efb32062c08170a05eeb8
        6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918
        6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
        7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451
        d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35
        e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683
        ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d""".split()
    ),
    "BeamType": frozenset({"0e19f02ca15d6060d63dc1946cc784d739c69a4cc5e6ef266a50e3b58c673f35"}),
    "BodyPartExamined": frozenset({"c627c09c14e58e44bc51622dac392958ec88244e414b508020634f53cfcd1e69"}),
    "ConvolutionKernel": frozenset({"5df99372cd81a643bd203fc74e7bb655691ed5938bfbcef4fb6b45d10d8112ca"}),
    "DoseReferenceDescription": frozenset({"f6e0a1e2ac41945a9aa7ff8a8aaa0cebc12a3bcc981a929ad5cf810a090e11ae"}),
    "DoseReferenceStructureType": frozenset(
        """3e8d3243e99cf9bb513f98ff18b8785a89c97efa9599a6b612a3cf2ca8fa263f
        4e8a59f9078d8cbca81b5197f3639b93ebeeaf479136b397c98a326f69966186""".split()
    ),
    "DoseReferenceType": frozenset({"3dc0db889344edf0b87069519efcdfc547733444a32a489366523a80a89f852c"}),
    "DoseSummationType": frozenset(
        """0ff15403106fefdaa7a0816f2c17f1fd4e4e1c065feb6194a07df811dc03d188
        248c4fe30ad4a33a233b2bfa053f88b6d6f532d23eb9221bf50c5c2dc167a150""".split()
    ),
    "DoseType": frozenset({"c490f246adfef8b03e3e1342be32c3e11e93390fd94dcebea55082872226af55"}),
    "DoseUnits": frozenset({"c79a94a92d8db5323f4fe2a3ef291a67111ed7f7de529758fd6ced19fa0f519f"}),
    "FilterType": frozenset({"5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9"}),
    "FluenceMode": frozenset({"335fd665f279a081079a603243547268742c8e8d0af2f06b6a4b09b40c06e243"}),
    "GantryRotationDirection": frozenset({"c627c09c14e58e44bc51622dac392958ec88244e414b508020634f53cfcd1e69"}),
    "ImageType": frozenset(
        """181361118af17d7f5d1f1c9cd66745aa2cc02f64daf2c4fe7e9f827d333120a8
        af81d56e26e1e74a2a1e37675c1c946c05d33dd0aec09507cc7de51ac667d5bf
        bc9a66886ccb7818fe8efe9d5703f0494c5c9cbf3afc4e1b74ba89975d5b73f5""".split()
    ),
    "ImplementationVersionName": frozenset({"bbf208aca05e9f056f142144d3e8fe5ee6e256aaa53f07785b30a5025ffd9463"}),
    # Human-reviewed as non-identifying; retain only its fingerprint.
    "InstitutionalDepartmentName": frozenset({"4c6f412d43493208daf7185186bec5416f95163fa7dc61ee578d22ec407bf5d0"}),
    "InstitutionName": frozenset({"1388ff906e5a6caacb08d03618dab3572bcf9473552cc2576fdb1803339ea4aa"}),
    "Manufacturer": frozenset({"40b77fd21cc5d6ad262e1df97bc2b0f384e9a9b176d9f0e1d4d9b44312836c42"}),
    "Modality": frozenset(
        """15cbe5f066da796145940479d571424695e3077a1de270cb04972942d5b16260
        61a8e6e21298a18c3d652ce46dd99931d3cc851c401db229ffeb3a7f7836c566
        ea9d08281d8e328805625c9dc40f518ae22a187434d36b02b023acff48c5df79""".split()
    ),
    "OtherPatientIDs": frozenset({"78f7b19d196f986a716d3a48e531e5dee7d0d67726646904e800b222b60ee53f"}),
    "OtherPatientNames": frozenset({"6df143b5f70157578d1e535277c5c95e0ded34f11e4a31cdb5e87b8814afd7c4"}),
    "PatientID": frozenset(
        """bd2bf88ec9fb246425bf2db78843d1c80b07beb7c2f044848cad02eded6e350e
        f0c2e7c33658e841ae0fc6c9c505910d4615d1eede71eebc2e052ad19760ff10""".split()
    ),
    "PatientName": frozenset({"9dbf8057012e99a692df37f984b92232c1aeee59ba9576be9f440d2ae0bef774"}),
    "PatientPosition": frozenset({"53966741de55a5a07fcad5a9f58f03730bfd0fac91de200c05580fd942b4709b"}),
    "PatientSex": frozenset({"c4694f2e93d5c4e7d51f9c5deb75e6cc8be5e1114178c6a45b6fc2c566a0aa8c"}),
    "PatientSupportRotationDirection": frozenset({"c627c09c14e58e44bc51622dac392958ec88244e414b508020634f53cfcd1e69"}),
    "PhotometricInterpretation": frozenset({"871b68363d7c79970357c2834fc00bdd63031b00a0ecd028856816774ab72f8f"}),
    "PlanIntent": frozenset({"be92c40082f80dd5128e9c9a6538c1c8ffafd945471fa93f9b84e22c11843fae"}),
    "PrescriptionDescription": frozenset({"0620c20491091c805fb4ae120989441c5dc353272c312a680bc524f33dc41cad"}),
    "PrimaryDosimeterUnit": frozenset({"a24c631b902b547e715a74cee7e4d2947dac4334b2ee27dbd4dccdd22e9f2ced"}),
    "ProtocolName": frozenset({"e6c252b3856a8c4024efba6f1cdb459f39c8a181400322d2638c1b46f5ef0d0d"}),
    "RTBeamLimitingDeviceType": frozenset(
        """aa28e11f9e1515364cbe5d75220bbbc368b234dbe8ebc132adace76c5d862935
        c3dd9203996880d9de4ceda96ec7d75cd058b9a7685b738e1884a5f671a0f613""".split()
    ),
    "RTPlanGeometry": frozenset({"0a935ec18ca52f08785c9c17d0160d1d62115348cc808392033fcef3e93c6d5c"}),
    "RTPlanLabel": frozenset(
        """35c1fa59e0bec0b4b119f372cb64381e2ae2290bc56bebb54cbfcab6569f3535
        55b6fc580fa980c49d6bd240cace977ef747bf89c8867cf18ae7833ca23ed1db
        76ea48af5908fcf889bec58affdb8c29fce29db2b751fa719baa49042c5b0b98
        86536f19c7e0f472d95fb01b109c63642eafd7505e5127df374b4de54842e2e4
        9f5a29dcc42ebbe51cd581d4a6f8c1ec09405505eec24d80de4f647b6065b142
        e5e5b2c0b4818a548d307a10ac6171289c061ab25b81a47d74e41ef9d2ae9d85""".split()
    ),
    "RTPlanName": frozenset(
        """2f6ef5ab683e3f59dceafb1c98c32b675dfe76a1ff81dcfcd857ffb4a11faa5f
        5bea03735e4603abe9fa2484ef99a1b0d35d878ffb6b69a40588e86a5307d288
        68b164e487c6f57de87d58cbd376276c86fbe1da45fde92600396dcfb1f09d33
        6f783d638673bb49dd61ae4a9c1de45f91cc76f8b0c73d4806d45e7e8f583bdb
        9c3f60740cf868ef435a3752bab7f5e5cf2badf32805973dcd371da8ec8fe843
        a8739caa827abc31c5bff9441f7d60228cd5cccb44b897c13e807534b0d4d374""".split()
    ),
    "RadiationType": frozenset({"ff6945dda8c3e7d7d9642e1cfd805a1b3f563f990833c5d49b1425a90826a918"}),
    "ReferringPhysicianName": frozenset({"670f60e6b8e1bb4676af2d1916a8fef8af98f19fdaf4267401b6f1906988326d"}),
    "RotationDirection": frozenset({"05e24533723eed43de1bac6e050543e590ed397c5b729499a9ea53ff7329cee0"}),
    "SetupTechnique": frozenset({"4026b6f19a8e88ff5b99385ce896c6d2eee0badebeea3e68471e2444dd90034e"}),
    "SoftwareVersions": frozenset(
        """7d52ce839c315cece1a69db982ad437b0da66ee5620c6ed0406786caf57efa4e
        fb181bd90fcec5b906761fe5790994547ec82d8b9bae973a5255f4178bf0d52c""".split()
    ),
    "SpecificCharacterSet": frozenset({"3484aff0aa43236e2ea0c5635005843a92b985c0e487475e663e63d790d92653"}),
    "StationName": frozenset({"2cd8e3f88432c8307c90cbf44694d636f6ca6e6ebeb600b45765dd5ef6347185"}),
    "StudyDescription": frozenset(
        """ae84d27d259c61d655967e0758a2671999dd0deb733ef5de89749f041f609d24
        b9a23605b1825e29372b043bc998e508e177042869c82e436e8fb274dbac84a4""".split()
    ),
    "StudyID": frozenset(
        """b1c6d20d4da3f375a6ace10bbd196224f496001353a9e81110348209ecc85f78
        f33ad84452593b3df8401571bb6ac99f173e40fa704b898c3cb48270171bff3b""".split()
    ),
    "TableTopEccentricRotationDirection": frozenset({"c627c09c14e58e44bc51622dac392958ec88244e414b508020634f53cfcd1e69"}),
    "TissueHeterogeneityCorrection": frozenset({"556728f7f45600acafc8914a6b4f1d2bfb607385b1fe49e2c74e7ef657171dee"}),
    "ToleranceTableLabel": frozenset({"ef915c05396a0b76088b564cc13439c3554c6d9aec732968dce72e315578d1d0"}),
    "TreatmentDeliveryType": frozenset({"a41297525ca556ff593ce37b720994c8cc83c1fe4dcdfa803cca3420f01ff5f2"}),
    "TreatmentMachineName": frozenset({"9e5c9e49d50dc679b79343cd97637865d05adca380d9ee92d8ba53dfd7571080"}),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def text_values(value: object) -> list[str]:
    if isinstance(value, (MultiValue, list, tuple)):
        return ["" if item is None else str(item).strip() for item in value]
    if value is None:
        return [""]
    return [str(value).strip()]


def text_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def private_value_reference(value: object) -> str:
    normalized = str(value).strip()
    return f"length={len(normalized)} sha256={text_fingerprint(normalized)[:16]}"


def structured_text_is_allowed(vr: str, keyword: str, value: str) -> bool:
    if vr == "AS":
        return bool(AS_PATTERN.fullmatch(value))
    if vr == "DA":
        return bool(DA_PATTERN.fullmatch(value))
    if vr == "DS":
        return len(value) <= 16 and bool(DS_PATTERN.fullmatch(value))
    if vr == "DT":
        return len(value) <= 26 and bool(DT_PATTERN.fullmatch(value))
    if vr == "IS":
        return len(value) <= 12 and bool(IS_PATTERN.fullmatch(value))
    if vr == "TM":
        return len(value) <= 16 and bool(TM_PATTERN.fullmatch(value))
    if vr == "UI":
        if len(value) > 64 or not UI_PATTERN.fullmatch(value):
            return False
        return (
            value.startswith("1.2.840.10008.")
            or value.startswith(PYDICOM_ROOT_UID)
            or (keyword == "InstanceCreatorUID" and value == VENDOR_INSTANCE_CREATOR_UID)
        )
    raise AssertionError(f"unhandled structured text VR: {vr}")


def audit_text_elements(
    dataset: pydicom.dataset.Dataset,
    relative: str,
    errors: list[str],
    seen: set[tuple[str, str, str, str, str]] | None = None,
) -> None:
    """Audit every textual element, including elements in nested sequences."""
    if seen is None:
        seen = set()
    for element in dataset.iterall():
        if element.VR not in HUMAN_READABLE_VRS:
            continue
        keyword = element.keyword or "<unknown>"
        for value in text_values(element.value):
            if not value:
                continue
            digest = text_fingerprint(value)
            if element.VR in STRUCTURED_TEXT_VRS:
                allowed = structured_text_is_allowed(element.VR, keyword, value)
            else:
                allowed = digest in ALLOWED_TEXT_FINGERPRINTS.get(keyword, frozenset())
            if allowed:
                continue
            finding = (relative, str(element.tag), keyword, element.VR, digest)
            if finding in seen:
                continue
            seen.add(finding)
            errors.append(
                f"unapproved DICOM text: {relative}: tag={element.tag} "
                f"keyword={keyword} VR={element.VR} length={len(value)} "
                f"sha256={digest[:16]}"
            )


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
    audit_warnings: list[str] = []
    modalities: Counter[str] = Counter()
    cases: dict[str, list[tuple[Path, object]]] = defaultdict(list)
    sop_paths: dict[str, list[Path]] = defaultdict(list)
    missing_burned_in_annotation = 0
    seen_text_findings: set[tuple[str, str, str, str, str]] = set()

    if not files:
        errors.append("no DICOM files found")

    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        if path.stat().st_size >= GITHUB_HARD_LIMIT:
            errors.append(f"file is at or above 100 MiB: {relative}")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                dataset = pydicom.dcmread(path, stop_before_pixels=True)
        except Exception as exc:
            errors.append(f"cannot parse {relative}: {type(exc).__name__}")
            continue

        audit_text_elements(dataset.file_meta, relative, errors, seen_text_findings)
        audit_text_elements(dataset, relative, errors, seen_text_findings)

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
                errors.append(
                    f"unexpected {keyword}: {relative}: {private_value_reference(value)}"
                )
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
                errors.append(
                    f"unexpected person-name value: {relative}: tag={element.tag} "
                    f"VR=PN {private_value_reference(element.value)}"
                )

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
        errors.append(
            f"duplicate SOPInstanceUID {private_value_reference(uid)}: {shown}"
        )

    if missing_burned_in_annotation:
        audit_warnings.append(
            f"BurnedInAnnotation is absent from {missing_burned_in_annotation} files; "
            "representative pixels require visual review"
        )

    if args.check_checksums:
        verify_checksums(files, errors)

    for warning in audit_warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)

    total = sum(path.stat().st_size for path in files)
    print(
        f"Audited {len(files)} files ({total / 1024 / 1024:.2f} MiB): "
        f"{dict(sorted(modalities.items()))}"
    )
    print(
        f"Cases: {len(cases)}; warnings: {len(audit_warnings)}; "
        f"errors: {len(errors)}"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception as exc:
        print(f"ERROR: audit failed safely: {type(exc).__name__}", file=sys.stderr)
        exit_code = 1
    raise SystemExit(exit_code)
