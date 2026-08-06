from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import re
import struct
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import warnings

import pydicom
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.dataelem import RawDataElement
from pydicom.sequence import Sequence
from pydicom.tag import Tag
from pydicom.uid import (
    CTImageStorage,
    ExplicitVRLittleEndian,
    PYDICOM_IMPLEMENTATION_UID,
    generate_uid,
)

from scripts import audit_dicom


SENTINEL = "SITE_TOKEN_12345"
REVIEWED_DEPARTMENT_FINGERPRINT = (
    "4c6f412d43493208daf7185186bec5416f95163fa7dc61ee578d22ec407bf5d0"
)


class TextAuditTests(unittest.TestCase):
    def audit(self, dataset: Dataset) -> list[str]:
        errors: list[str] = []
        audit_dicom.audit_text_elements(dataset, "case/example.dcm", errors)
        return errors

    def assert_secret_is_redacted(self, errors: list[str]) -> None:
        self.assertTrue(errors)
        joined = "\n".join(errors)
        self.assertNotIn(SENTINEL, joined)
        self.assertIn(audit_dicom.text_fingerprint(SENTINEL)[:16], joined)

    def test_allows_reviewed_text_and_structured_values(self) -> None:
        dataset = Dataset()
        dataset.PatientName = "ANONYMOUS"
        dataset.BurnedInAnnotation = "NO"
        dataset.PregnancyStatus = None
        dataset.SliceThickness = None
        dataset.SOPClassUID = CTImageStorage
        dataset.SOPInstanceUID = generate_uid()

        self.assertEqual([], self.audit(dataset))

        file_meta = FileMetaDataset()
        file_meta.FileMetaInformationVersion = b"\0\1"
        self.assertEqual([], self.audit(file_meta))

    def test_department_policy_contains_only_reviewed_fingerprint(self) -> None:
        self.assertIn(
            REVIEWED_DEPARTMENT_FINGERPRINT,
            audit_dicom.ALLOWED_TEXT_FINGERPRINTS["InstitutionalDepartmentName"],
        )

    def test_rejects_unreviewed_free_text_without_disclosing_it(self) -> None:
        dataset = Dataset()
        dataset.InstitutionalDepartmentName = SENTINEL

        errors = self.audit(dataset)

        self.assert_secret_is_redacted(errors)
        self.assertRegex(errors[0], r"tag=\(0008,\s*1040\)")
        self.assertIn("VR=LO", errors[0])

    def test_rejects_nonempty_ae_title(self) -> None:
        dataset = Dataset()
        dataset.RetrieveAETitle = SENTINEL

        errors = self.audit(dataset)

        self.assert_secret_is_redacted(errors)
        self.assertIn("VR=AE", errors[0])

    def test_rejects_unreviewed_text_in_nested_sequence(self) -> None:
        item = Dataset()
        item.SeriesDescription = SENTINEL
        dataset = Dataset()
        dataset.BeamSequence = Sequence([item])

        errors = self.audit(dataset)

        self.assert_secret_is_redacted(errors)
        self.assertIn("keyword=SeriesDescription", errors[0])

    def test_enforces_identity_policy_in_nested_sequence(self) -> None:
        disguised_birth_date = "20000101"
        item = Dataset()
        item.PatientBirthDate = disguised_birth_date
        dataset = Dataset()
        dataset.OriginalAttributesSequence = Sequence([item])

        errors = self.audit(dataset)

        self.assertEqual(1, len(errors))
        self.assertNotIn(disguised_birth_date, errors[0])
        self.assertIn(
            audit_dicom.text_fingerprint(disguised_birth_date)[:16], errors[0]
        )
        self.assertIn("keyword=PatientBirthDate", errors[0])
        self.assertIn("VR=DA", errors[0])

    def test_rejects_structured_patient_characteristics(self) -> None:
        for keyword, value, vr in (
            ("PatientBirthTime", "123456", "TM"),
            ("PatientAge", "037Y", "AS"),
            ("PatientWeight", "72.5", "DS"),
            ("MeasuredAPDimension", "18.5", "DS"),
            ("MeasuredLateralDimension", "31.5", "DS"),
            ("ExaminedBodyThickness", 22.5, "FL"),
        ):
            with self.subTest(keyword=keyword):
                text_value = str(value)
                item = Dataset()
                setattr(item, keyword, value)
                dataset = Dataset()
                dataset.OriginalAttributesSequence = Sequence([item])

                errors = self.audit(dataset)

                self.assertEqual(1, len(errors))
                self.assertNotIn(text_value, errors[0])
                self.assertIn(
                    audit_dicom.text_fingerprint(text_value)[:16], errors[0]
                )
                self.assertIn(f"keyword={keyword}", errors[0])
                self.assertIn(f"VR={vr}", errors[0])

    def test_rejects_numeric_patient_characteristic_in_nested_sequence(self) -> None:
        item = Dataset()
        item.PregnancyStatus = 4
        dataset = Dataset()
        dataset.OriginalAttributesSequence = Sequence([item])

        errors = self.audit(dataset)

        self.assertEqual(1, len(errors))
        self.assertIn(audit_dicom.text_fingerprint("4")[:16], errors[0])
        self.assertIn("non-empty protected DICOM attribute", errors[0])
        self.assertIn("keyword=PregnancyStatus", errors[0])
        self.assertIn("VR=US", errors[0])

    def test_rejects_unreviewed_public_bulk_data(self) -> None:
        dataset = Dataset()
        dataset.EncapsulatedDocument = SENTINEL.encode("utf-8")

        errors = self.audit(dataset)

        self.assert_secret_is_redacted(errors)
        self.assertIn("unapproved DICOM bulk data", errors[0])
        self.assertIn("keyword=EncapsulatedDocument", errors[0])
        self.assertIn("VR=OB", errors[0])

    def test_rejects_nested_pixel_data_but_skips_root_pixel_data(self) -> None:
        dataset = Dataset()
        dataset.PixelData = SENTINEL.encode("utf-8")
        icon = Dataset()
        icon.PixelData = SENTINEL.encode("utf-8")
        dataset.IconImageSequence = Sequence([icon])

        errors = self.audit(dataset)

        self.assert_secret_is_redacted(errors)
        self.assertEqual(1, len(errors))
        self.assertIn("unapproved DICOM bulk data", errors[0])
        self.assertRegex(errors[0].lower(), r"tag=\(7fe0,\s*0010\)")

    def test_rejects_unreviewed_file_meta_text(self) -> None:
        file_meta = FileMetaDataset()
        file_meta.ImplementationVersionName = SENTINEL

        errors = self.audit(file_meta)

        self.assert_secret_is_redacted(errors)
        self.assertIn("keyword=ImplementationVersionName", errors[0])

    def test_rejects_unknown_public_un_element_without_disclosing_it(self) -> None:
        dataset = Dataset()
        dataset.add_new((0x7776, 0x0010), "UN", SENTINEL.encode("utf-8"))

        errors = self.audit(dataset)

        self.assert_secret_is_redacted(errors)
        self.assertIn("unknown public DICOM element", errors[0])
        self.assertIn("VR=UN", errors[0])

    def test_rejects_unknown_public_structured_element(self) -> None:
        disguised_token = "20250101"
        dataset = Dataset()
        dataset.add_new((0x7776, 0x0012), "DA", disguised_token)

        errors = self.audit(dataset)

        self.assertEqual(1, len(errors))
        self.assertNotIn(disguised_token, errors[0])
        self.assertIn(
            audit_dicom.text_fingerprint(disguised_token)[:16], errors[0]
        )
        self.assertIn("unknown public DICOM element", errors[0])
        self.assertIn("VR=DA", errors[0])

    def test_rejects_public_tag_vr_mismatch(self) -> None:
        disguised_token = "20250101"
        dataset = Dataset()
        dataset.add_new((0x0008, 0x0080), "DA", disguised_token)

        errors = self.audit(dataset)

        self.assertEqual(1, len(errors))
        self.assertNotIn(disguised_token, errors[0])
        self.assertIn(
            audit_dicom.text_fingerprint(disguised_token)[:16], errors[0]
        )
        self.assertIn("DICOM VR mismatch", errors[0])
        self.assertIn("keyword=InstitutionName", errors[0])
        self.assertIn("VR=DA expected=LO", errors[0])

    def test_audits_trailing_element_without_loading_pixel_data(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "trailing.dcm"
            file_meta = FileMetaDataset()
            file_meta.MediaStorageSOPClassUID = CTImageStorage
            file_meta.MediaStorageSOPInstanceUID = generate_uid()
            file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
            file_meta.ImplementationClassUID = PYDICOM_IMPLEMENTATION_UID
            dataset = FileDataset(
                str(path), {}, file_meta=file_meta, preamble=b"\0" * 128
            )
            dataset.SOPClassUID = file_meta.MediaStorageSOPClassUID
            dataset.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
            dataset.BitsAllocated = 16
            dataset.PixelData = b"\0" * 2048
            dataset.add_new((0x8000, 0x0010), "LO", SENTINEL)
            dataset.save_as(path, write_like_original=False)

            audited = pydicom.dcmread(path, defer_size=1)
            raw_pixel_data = audited._dict[Tag(0x7FE0, 0x0010)]
            self.assertIsInstance(raw_pixel_data, RawDataElement)
            self.assertIsNone(raw_pixel_data.value)

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                errors = self.audit(audited)

            self.assert_secret_is_redacted(errors)
            self.assertIn("unknown public DICOM element", errors[0])
            self.assertIs(audited._dict[Tag(0x7FE0, 0x0010)], raw_pixel_data)

    def test_rejects_duplicate_tag_before_dataset_overwrite(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "duplicate.dcm"
            file_meta = FileMetaDataset()
            file_meta.MediaStorageSOPClassUID = CTImageStorage
            file_meta.MediaStorageSOPInstanceUID = generate_uid()
            file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
            file_meta.ImplementationClassUID = PYDICOM_IMPLEMENTATION_UID
            dataset = FileDataset(
                str(path), {}, file_meta=file_meta, preamble=b"\0" * 128
            )
            dataset.SOPClassUID = file_meta.MediaStorageSOPClassUID
            dataset.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
            dataset.InstitutionName = "ANONYMOUS_INSTIT"
            dataset.is_implicit_VR = False
            dataset.is_little_endian = True
            dataset.save_as(path, write_like_original=False)

            encoded = SENTINEL.encode("ascii")
            if len(encoded) % 2:
                encoded += b" "
            duplicate = (
                struct.pack("<HH", 0x0008, 0x0080)
                + b"LO"
                + struct.pack("<H", len(encoded))
                + encoded
            )
            original = path.read_bytes()
            approved_element = original.index(b"\x08\x00\x80\x00LO")
            path.write_bytes(
                original[:approved_element]
                + duplicate
                + original[approved_element:]
            )

            with self.assertRaises(
                audit_dicom.DuplicateDataElementError
            ) as raised:
                audit_dicom.dcmread_for_audit(path)

        self.assertEqual(Tag(0x0008, 0x0080), raised.exception.tag)
        self.assertNotIn(SENTINEL, str(raised.exception))

    def test_rejects_unapproved_uid_root_without_disclosing_it(self) -> None:
        unapproved_uid = "1.3.6.1.4.1.55555.1"
        dataset = Dataset()
        dataset.StudyInstanceUID = unapproved_uid

        errors = self.audit(dataset)

        self.assertEqual(1, len(errors))
        self.assertNotIn(unapproved_uid, errors[0])
        self.assertIn(audit_dicom.text_fingerprint(unapproved_uid)[:16], errors[0])
        self.assertIn("VR=UI", errors[0])

    def test_rejects_unregistered_standard_root_uid(self) -> None:
        unregistered_uid = "1.2.840.10008.999999999"
        dataset = Dataset()
        dataset.StudyInstanceUID = unregistered_uid

        errors = self.audit(dataset)

        self.assertEqual(1, len(errors))
        self.assertNotIn(unregistered_uid, errors[0])
        self.assertIn(
            audit_dicom.text_fingerprint(unregistered_uid)[:16], errors[0]
        )
        self.assertIn("VR=UI", errors[0])

    def test_rejects_registered_definition_uid_in_instance_field(self) -> None:
        dataset = Dataset()
        dataset.StudyInstanceUID = CTImageStorage

        errors = self.audit(dataset)

        self.assertEqual(1, len(errors))
        self.assertNotIn(str(CTImageStorage), errors[0])
        self.assertIn(
            audit_dicom.text_fingerprint(str(CTImageStorage))[:16], errors[0]
        )
        self.assertIn("keyword=StudyInstanceUID", errors[0])
        self.assertIn("VR=UI", errors[0])

    def test_rejects_unreviewed_clinical_timestamp(self) -> None:
        unreviewed_date = "20250101"
        dataset = Dataset()
        dataset.StudyDate = unreviewed_date

        errors = self.audit(dataset)

        self.assertEqual(1, len(errors))
        self.assertNotIn(unreviewed_date, errors[0])
        self.assertIn(
            audit_dicom.text_fingerprint(unreviewed_date)[:16], errors[0]
        )
        self.assertIn("keyword=StudyDate", errors[0])
        self.assertIn("VR=DA", errors[0])

    def test_rejects_zero_padded_uid_component(self) -> None:
        self.assertFalse(
            audit_dicom.structured_text_is_allowed(
                "UI", "SOPClassUID", "1.2.840.10008.01"
            )
        )
        self.assertTrue(
            audit_dicom.structured_text_is_allowed(
                "UI", "SOPClassUID", str(CTImageStorage)
            )
        )

    def test_validates_calendar_and_clock_ranges(self) -> None:
        for vr, value in (
            ("DA", "20250229"),
            ("DT", "20250231235959"),
            ("DT", "20240229240000"),
            ("DT", "20240229235959+1401"),
            ("IS", "2147483648"),
            ("IS", "999999999999"),
            ("TM", "246000"),
            ("TM", "235961"),
        ):
            with self.subTest(vr=vr, value=value):
                self.assertFalse(
                    audit_dicom.structured_text_is_allowed(vr, "Example", value)
                )

        for vr, value in (
            ("DA", "20240229"),
            ("DT", "2024"),
            ("DT", "20240229235960-1200"),
            ("IS", "-2147483648"),
            ("IS", "2147483647"),
            ("TM", "23"),
            ("TM", "235960.123456"),
        ):
            with self.subTest(vr=vr, value=value):
                self.assertTrue(
                    audit_dicom.structured_text_is_allowed(vr, "Example", value)
                )

    def test_cli_output_does_not_disclose_unreviewed_value(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            case = root / "case"
            case.mkdir()
            path = case / "example.dcm"

            file_meta = FileMetaDataset()
            file_meta.MediaStorageSOPClassUID = CTImageStorage
            file_meta.MediaStorageSOPInstanceUID = generate_uid()
            file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
            file_meta.ImplementationClassUID = PYDICOM_IMPLEMENTATION_UID
            dataset = FileDataset(
                str(path), {}, file_meta=file_meta, preamble=b"\0" * 128
            )
            dataset.SOPClassUID = file_meta.MediaStorageSOPClassUID
            dataset.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
            dataset.StudyInstanceUID = generate_uid()
            dataset.FrameOfReferenceUID = generate_uid()
            dataset.Modality = SENTINEL
            dataset.InstitutionalDepartmentName = SENTINEL
            dataset.save_as(path, write_like_original=False)

            stdout = StringIO()
            stderr = StringIO()
            original_audit_text_elements = audit_dicom.audit_text_elements

            def warn_during_traversal(*args: object, **kwargs: object) -> None:
                warnings.warn(SENTINEL)
                original_audit_text_elements(*args, **kwargs)

            with (
                patch.object(audit_dicom, "ROOT", root),
                patch.object(sys, "argv", ["audit_dicom.py"]),
                patch.object(
                    audit_dicom,
                    "audit_text_elements",
                    side_effect=warn_during_traversal,
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                result = audit_dicom.main()

        output = stdout.getvalue() + stderr.getvalue()
        self.assertEqual(1, result)
        self.assertNotIn(SENTINEL, output)
        self.assertIn(audit_dicom.text_fingerprint(SENTINEL)[:16], output)
        self.assertIn("keyword=InstitutionalDepartmentName", output)


if __name__ == "__main__":
    unittest.main()
