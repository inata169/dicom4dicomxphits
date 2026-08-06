from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.sequence import Sequence
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
        dataset.StudyDate = "19000101"
        dataset.SliceThickness = None
        dataset.SOPClassUID = CTImageStorage
        dataset.SOPInstanceUID = generate_uid()

        self.assertEqual([], self.audit(dataset))

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

    def test_rejects_unreviewed_file_meta_text(self) -> None:
        file_meta = FileMetaDataset()
        file_meta.ImplementationVersionName = SENTINEL

        errors = self.audit(file_meta)

        self.assert_secret_is_redacted(errors)
        self.assertIn("keyword=ImplementationVersionName", errors[0])

    def test_rejects_unapproved_uid_root_without_disclosing_it(self) -> None:
        unapproved_uid = "1.3.6.1.4.1.55555.1"
        dataset = Dataset()
        dataset.StudyInstanceUID = unapproved_uid

        errors = self.audit(dataset)

        self.assertEqual(1, len(errors))
        self.assertNotIn(unapproved_uid, errors[0])
        self.assertIn(audit_dicom.text_fingerprint(unapproved_uid)[:16], errors[0])
        self.assertIn("VR=UI", errors[0])

    def test_validates_calendar_and_clock_ranges(self) -> None:
        for vr, value in (
            ("DA", "20250229"),
            ("DT", "20250231235959"),
            ("DT", "20240229240000"),
            ("DT", "20240229235959+1401"),
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
            with (
                patch.object(audit_dicom, "ROOT", root),
                patch.object(sys, "argv", ["audit_dicom.py"]),
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
