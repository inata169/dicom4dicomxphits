# Contributing data

This repository accepts only confirmed non-patient phantom DICOM data needed by
`dicomxphits`. Never add patient, volunteer, clinical, licensed vendor, PHITS,
RT-PHITS, credential, or generated workspace files.

## Required checklist

Before committing a new or changed DICOM set:

1. Confirm from provenance records that the subject is a non-patient phantom.
2. De-identify the data before copying it into this repository. File names and
   directory names must not contain original identifiers or UIDs.
3. Review direct identifiers, nested sequences, private elements, overlays, and
   representative pixels. De-identification is not proven by changing only
   `PatientName`.
4. Keep one case per top-level directory using `CT/CTnnnnnn.dcm`,
   `RTPLAN.dcm`, and `RTDOSE/RTDOSE_*.dcm` names.
5. Ensure each RT Dose references the RT Plan shipped in the same case and that
   Study and Frame of Reference UIDs remain internally consistent.
6. Run:

   ```powershell
   py -3.12 scripts/audit_dicom.py
   py -3.12 scripts/update_checksums.py
   py -3.12 scripts/audit_dicom.py --check-checksums
   ```

7. Review `git status`, the staged paths, and file sizes before uploading.

Do not alter pixel values, geometry, dose, UIDs, or references merely to make an
audit pass. Stop and investigate the source instead. If potential identifying
information has already been committed, follow [SECURITY.md](SECURITY.md).
