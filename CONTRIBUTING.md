# Contributing data

This repository accepts only confirmed non-patient phantom DICOM data needed by
`dicomxphits`. Never add patient, volunteer, clinical, licensed vendor, PHITS,
RT-PHITS, credential, or generated workspace files.

## Required checklist

Before committing a new or changed DICOM set:

1. Confirm from provenance records that the subject is a non-patient phantom.
2. Confirm from provenance and permission records that the data may be published
   on GitHub, including public viewing and forking under GitHub's Terms of
   Service, and made available under [DATA_USE_TERMS.md](DATA_USE_TERMS.md).
3. De-identify the data before copying it into this repository. File names and
   directory names must not contain original identifiers or UIDs.
4. Review direct identifiers, nested sequences, private elements, overlays, and
   representative pixels. De-identification is not proven by changing only
   `PatientName`.
5. Keep one case per top-level directory using `CT/CTnnnnnn.dcm`,
   `RTPLAN.dcm`, and `RTDOSE/RTDOSE_*.dcm` names.
6. Ensure each RT Dose references the RT Plan shipped in the same case and that
   Study and Frame of Reference UIDs remain internally consistent.
7. Run:

   ```powershell
   py -3.12 scripts/audit_dicom.py
   py -3.12 scripts/update_checksums.py
   py -3.12 scripts/audit_dicom.py --check-checksums
   ```

8. Review `git status`, the staged paths, and file sizes before uploading.

Do not alter pixel values, geometry, dose, UIDs, or references merely to make an
audit pass. Stop and investigate the source instead. If potential identifying
information has already been committed, follow [SECURITY.md](SECURITY.md).
