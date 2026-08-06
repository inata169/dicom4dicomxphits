"""Fail-closed privacy and integrity audit for this DICOM data repository."""

from __future__ import annotations

import argparse
from datetime import date
import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path
import sys
import warnings

import pydicom
from pydicom.datadict import dictionary_VR
from pydicom.multival import MultiValue
from pydicom.tag import Tag
from pydicom.uid import PYDICOM_ROOT_UID, UID_dictionary


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"
GITHUB_HARD_LIMIT = 100 * 1024 * 1024
PIXEL_DATA_TAG = Tag(0x7FE00010)

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
BULK_DATA_VRS = {"OB", "OD", "OF", "OL", "OV", "OW"}
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
UI_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*$")
EXPECTED_MODALITIES = Counter({"CT": 426, "RTDOSE": 20, "RTPLAN": 6})

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
    "EthnicGroup",
    "InstitutionAddress",
    "OperatorsName",
    "LastMenstrualDate",
    "Occupation",
    "PatientAddress",
    "PatientAge",
    "PatientBirthTime",
    "PatientBodyMassIndex",
    "PatientReligiousPreference",
    "PatientSize",
    "PatientTelephoneNumbers",
    "PatientWeight",
    "PerformingPhysicianName",
    "RequestingPhysician",
    "ResponsibleOrganization",
    "ResponsiblePerson",
    "PregnancyStatus",
    "SmokingStatus",
}

ALLOWED_BULK_FINGERPRINTS = {
    "FileMetaInformationVersion": frozenset(
        {"b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2"}
    ),
}

# Existing de-identified fixture timestamps are approved per tag by fingerprint.
# New timestamp values fail closed even when their DA/DT/TM syntax is valid.
INSTANCE_CREATION_DATE_FINGERPRINTS = frozenset(
    """2d3ecd804da5d868a9a2918a0ad12813367984b2c49caf6323415999b33e4f9a
    34b466d3cf3e26747b388412c450470ca6a87ca0ba80f052aef274d5cf58d106
    36bc61e65df9a293d0f354521bd3c68f2dc225134ba2517fdc8d19443f74ebc6
    7ca741f9494062c8e6657d79d07a71d44c7c0e321a7f66c001d04cd8d69b9888
    c0dad314dc6afdb571e034478e96a7ee69bda4b903a7ac5526655a541b3f5894
    e11895539afe01eaf93e854dc8793acef2915986e1684f0c6f4a16c3553d334f
    f059deaa883e7f8d96a115b5c16be1e510da942c714eeb8618cf1e96e9ba222f""".split()
)
INSTANCE_CREATION_TIME_FINGERPRINTS = frozenset(
    """0fddc68432424eee3bc100bc7b0c5184f94c3beb3068d2de93825910669f2867
    1664b05244b7e2773449f5fe7b75f83566f0c94e08f5bb4b98da518ccb75abd4
    1c4a4dc5d941debcce758550753868a2ac4cb22b6c3475210948e7fd87aff471
    2e22818cbc67007170976f81568d4693ec1ea0b31c3a1d33001e9cd56c873fb4
    5e5c60b37556757232725325bf61f33a6d6c430eed70b60c179648e4eddac0e1
    6851aa4654f994dea13308ccd6e17a2ec947b529153e24291772f32526f9e7f3
    6cee7c4f765b63e56bd7d427328ad421638e56f1b8da6879f74f6db04bce94b6
    6db3e16c17015278c6adeaae521e202f90c45a8b5d578a40686d20639420aad1
    88cd242bc996ab0abdc9e750e0ac7926a6dd8eb177b142d7fbef6a8fa6e73c72
    8d1665ef70d520e5a03352392dd5398e3b5b190011c7c703cbaab555ff8a2c67
    953db8b003802d31b79515b01464522bd123cece6a7c83e5dd65fbbf5d6eac9d
    9fe1e0f70594e7d5309a21acd7bb4cc7ac516466504f5b4f4ad21e84129b6ff8
    b56c80a8df1b2ffc503e2d6c4de310b162aa9800b5ef469ee12dad28a326c6c7
    e22a866d8c3df1777ab6967e16bd3b9929771c4aa92fa355817425e872eb142e
    e8b14d9cbaba04ffc75b404e699243c2763705a34dc857cab3cd53cb5e26a6cd""".split()
)
COMMON_DATE_FINGERPRINTS = frozenset(
    {"2fa0f121daa18de5cdf751c1e6eb5b79ad30358364fff2deb63d7f2b855865de"}
)
COMMON_TIME_FINGERPRINTS = frozenset(
    {"79a49308880c653e1b7a82c8215929e7e3a3dcaa7806718210809172c6ebe03c"}
)
RT_PLAN_DATE_FINGERPRINTS = frozenset(
    """34b466d3cf3e26747b388412c450470ca6a87ca0ba80f052aef274d5cf58d106
    66cb8df1313805b003818d2580042fcf991cead9940e15c49709494d7a610169
    7ca741f9494062c8e6657d79d07a71d44c7c0e321a7f66c001d04cd8d69b9888
    e11895539afe01eaf93e854dc8793acef2915986e1684f0c6f4a16c3553d334f
    f059deaa883e7f8d96a115b5c16be1e510da942c714eeb8618cf1e96e9ba222f""".split()
)
RT_PLAN_TIME_FINGERPRINTS = frozenset(
    """08fcff9a786025d8a512837db7035a7b8f98c4003294bd8cee0c640ff0bb6b80
    289b28efbcfc82c4b45a43ff43d0510ff3b2883c5273c8a1fe8f3389bcc13e78
    3c66d5cd5e02852aff4ddce0081849a55aefc9ae07b8b01b6b8c5eff8f906282
    634c70adc7a1e4b7ea106237a6bd39971c2fb56baf3035a2492ff072f8adc9e4
    c0cccdc5e10248094cc37497cb84065cb370a4d4774b64e1616ee00321de0b25
    d08c4348abe3b9f69781fc8214d149cb3393a6c7d0ff3336f5788f6a80ad75d8""".split()
)
ALLOWED_TIMESTAMP_FINGERPRINTS = {
    "InstanceCreationDate": INSTANCE_CREATION_DATE_FINGERPRINTS,
    "InstanceCreationTime": INSTANCE_CREATION_TIME_FINGERPRINTS,
    "StudyDate": COMMON_DATE_FINGERPRINTS,
    "SeriesDate": COMMON_DATE_FINGERPRINTS,
    "ContentDate": COMMON_DATE_FINGERPRINTS,
    "StudyTime": COMMON_TIME_FINGERPRINTS,
    "SeriesTime": COMMON_TIME_FINGERPRINTS,
    "AcquisitionTime": COMMON_TIME_FINGERPRINTS,
    "ContentTime": COMMON_TIME_FINGERPRINTS,
    "DateOfLastCalibration": frozenset(
        {"caadcfa145d4c7491a15d9c251c180b8a0a96327693dc0979a75894d24c39264"}
    ),
    "TimeOfLastCalibration": frozenset(
        {"606fd020c6051250eaf82e695d36280d1ed8ca2669730d0114adb73b80f270eb"}
    ),
    "RTPlanDate": RT_PLAN_DATE_FINGERPRINTS,
    "RTPlanTime": RT_PLAN_TIME_FINGERPRINTS,
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
    "BurnedInAnnotation": frozenset({"23794d91c53ae875c8e247d72561e35d9d06ee07c70c9e0dbcc977a6d161504a"}),
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
    "StudyDescription": fçÎ­¢G§²ÚîÆ­yÞ tuple[int, str]:
    encoded = value if isinstance(value, bytes) else str(value).encode("utf-8", "surrogatepass")
    return len(encoded), hashlib.sha256(encoded).hexdigest()


def expected_public_vrs(tag: object) -> frozenset[str] | None:
    """Return the standard VR choices for a public tag, or None if unknown."""
    try:
        vr_definition = dictionary_VR(tag)
    except KeyError:
        return None
    return vr_choices(vr_definition)


def vr_choices(vr: str) -> frozenset[str]:
    return frozenset(part.strip() for part in vr.split(" or "))


def iter_auditable_elements(
    dataset: pydicom.dataset.Dataset,
    *,
    skip_root_pixel_data: bool = True,
):
    """Yield all elements, exempting only the visually reviewed root pixels."""
    for tag in dataset.keys():
        if tag == PIXEL_DATA_TAG and skip_root_pixel_data:
            continue
        element = dataset[tag]
        yield element
        if element.VR == "SQ":
            for item in element.value:
                yield from iter_auditable_elements(
                    item, skip_root_pixel_data=False
                )


def valid_da(value: str) -> bool:
    if not DA_PATTERN.fullmatch(value):
        return False
    try:
        date(int(value[:4]), int(value[4:6]), int(value[6:8]))
    except ValueError:
        return False
    return True


def valid_time_components(value: str) -> bool:
    basic = value.split(".", 1)[0]
    hour = int(basic[:2])
    minute = int(basic[2:4]) if len(basic) >= 4 else 0
    second = int(basic[4:6]) if len(basic) >= 6 else 0
    return hour <= 23 and minute <= 59 and second <= 60


def valid_dt(value: str) -> bool:
    if len(value) > 26 or not DT_PATTERN.fullmatch(value):
        return False

    core = value
    if len(core) >= 5 and core[-5] in "+-":
        offset = core[-5:]
        core = core[:-5]
        offset_minutes = int(offset[1:3]) * 60 + int(offset[3:5])
        if int(offset[3:5]) > 59:
            return False
        if offset[0] == "-":
            offset_minutes = -offset_minutes
        if not -12 * 60 <= offset_minutes <= 14 * 60:
            return False

    basic = core.split(".", 1)[0]
    year = int(basic[:4])
    if not 1 <= year <= 9999:
        return False
    if len(basic) >= 6 and not 1 <= int(basic[4:6]) <= 12:
        return False
    if len(basic) >= 8:
        try:
            date(year, int(basic[4:6]), int(basic[6:8]))
        except ValueError:
            return False
    if len(basic) >= 10 and int(basic[8:10]) > 23:
        return False
    if len(basic) >= 12 and int(basic[10:12]) > 59:
        return False
    if len(basic) >= 14 and int(basic[12:14]) > 60:
        return False
    return True


def structured_text_is_allowed(vr: str, keyword: str, value: str) -> bool:
    if vr == "AS":
        return bool(AS_PATTERN.fullmatch(value))
    if vr == "DA":
        return valid_da(value)
    if vr == "DS":
        return len(value) <= 16 and bool(DS_PATTERN.fullmatch(value))
    if vr == "DT":
        return valid_dt(value)
    if vr == "IS":
        return (
            len(value) <= 12
            and bool(IS_PATTERN.fullmatch(value))
            and -(2**31) <= int(value) <= 2**31 - 1
        )
    if vr == "TM":
        return (
            len(value) <= 16
            and bool(TM_PATTERN.fullmatch(value))
            and valid_time_components(value)
        )
    if vr == "UI":
        if len(value) > 64 or not UI_PATTERN.fullmatch(value):
            return False
        return (
            value in UID_dictionary
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
    for element in iter_auditable_elements(dataset):
        keyword = element.keyword or "<unknown>"
        actual_vrs = vr_choices(element.VR)
        expected_vrs = None if element.tag.is_private else expected_public_vrs(element.tag)
        if not element.tag.is_private and expected_vrs is None:
            length, digest = opaque_value_reference(element.value)
            finding = (relative, str(element.tag), keyword, element.VR, digest)
            if finding not in seen:
                seen.add(finding)
                errors.append(
                    f"unknown public DICOM element: {relative}: tag={element.tag} "
                    f"keyword={keyword} VR={element.VR} length={length} "
                    f"sha256={digest[:16]}"
                )
            continue
        if expected_vrs is not None and not actual_vrs.issubset(expected_vrs):
            length, digest = opaque_value_reference(element.value)
            finding = (relative, str(element.tag), keyword, element.VR, digest)
            if finding not in seen:
                seen.add(finding)
                errors.append(
                    f"DICOM VR mismatch: {relative}: tag={element.tag} "
                    f"keyword={keyword} VR={element.VR} "
                    f"expected={'/'.join(sorted(expected_vrs))} length={length} "
                    f"sha256={digest[:16]}"
                )
            continue
        if keyword in MUST_BE_EMPTY:
            for value in text_values(element.value):
                if not value:
                    continue
                digest = text_fingerprint(value)
                finding = (relative, str(element.tag), keyword, element.VR, digest)
                if finding not in seen:
                    seen.add(finding)
                    errors.append(
                        f"non-empty protected DICOM attribute: {relative}: "
                        f"tag={element.tag} keyword={keyword} VR={element.VR} "
                        f"length={len(value)} sha256={digest[:16]}"
                    )
            continue
        if actual_vrs & BULK_DATA_VRS:
            length, digest = opaque_value_reference(element.value)
            if digest in ALLOWED_BULK_FINGERPRINTS.get(keyword, frozenset()):
                continue
            finding = (relative, str(element.tag), keyword, element.VR, digest)
            if finding not in seen:
                seen.add(finding)
                errors.append(
                    f"unapproved DICOM bulk data: {relative}: tag={element.tag} "
                    f"keyword={keyword} VR={element.VR} length={length} "
                    f"sha256={digest[:16]}"
                )
            continue
        if element.VR not in HUMAN_READABLE_VRS:
            continue
        for value in text_values(element.value):
            if not value:
                continue
            digest = text_fingerprint(value)
            if keyword in EXPECTED_IDENTITIES:
                allowed = value in EXPECTED_IDENTITIES[keyword]
            elif element.VR in {"DA", "DT", "TM"}:
                allowed = digest in ALLOWED_TIMESTAMP_FINGERPRINTS.get(
                    keyword, frozenset()
                )
            elif element.VR in STRUCTURED_TEXT_VRS:
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

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return audit_repository(args)


def audit_repository(args: argparse.Namespace) -> int:

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
            # Parse through EOF so elements after Pixel Data cannot evade the
            # audit. Large values are deferred, and traversal skips Pixel Data.
            dataset = pydicom.dcmread(path, defer_size=1)
        except Exception as exc:
            errors.append(f"cannot parse {relative}: {type(exc).__name__}")
            continue

        audit_text_elements(dataset.file_meta, relative, errors, seen_text_findings)
        audit_text_elements(dataset, relative, errors, seen_text_findings)

        modality = str(getattr(dataset, "Modality", ""))
        modality_key = modality if modality in EXPECTED_MODALITIES else "<unapproved>"
        modalities[modality_key] += 1
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
        burned_in = str(getattr(dataset, "BurnedInAnnotation", "")).upper()
        if not burned_in:
            missing_burned_in_annotation += 1
        elif burned_in != "NO":
            errors.append(f"BurnedInAnnotation is not NO: {relative}")

        for element in iter_auditable_elements(dataset):
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

    if modalities != EXPECTED_MODALITIES:
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
