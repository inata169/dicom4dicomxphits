# dicom4dicomxphits

`dicom4dicomxphits` is the private, data-only companion repository for
[`inata169/dicomxphits`](https://github.com/inata169/dicomxphits). It contains
anonymized, non-patient water-phantom DICOM examples for education, research,
and local workflow validation.

> [!WARNING]
> These files are not for diagnosis, treatment planning, clinical
> commissioning, patient QA, or any other clinical use. They do not establish
> the clinical validity of `dicomxphits`, PHITS, RT-PHITS, or any treatment
> machine model.

This repository is for research and educational DICOM data used by
`dicomxphits`. Do not add patient data or use these files clinically.

See [docs/HANDOFF.md](docs/HANDOFF.md) for the current development status.

## Repository contents

Each case is self-contained:

```text
<case>/
├─ CT/
│  ├─ CT000001.dcm
│  └─ ...
├─ RTPLAN.dcm
└─ RTDOSE/
   ├─ RTDOSE_TOTAL.dcm  # total plan dose (DICOM DoseSummationType = PLAN)
   └─ RTDOSE_BEAMnnn.dcm   # present in selected cases
```

| Case | CT | RT Plan | RT Dose | Purpose |
| --- | ---: | ---: | ---: | --- |
| `PHITSgeoTest` | 71 | 1 | 7 | Geometry and multi-beam examples |
| `WaterPhantom-golden8` | 71 | 1 | 9 | Eight-field reference data and a coordinate-fixed derivative |
| `WaterPhantom03x03` | 71 | 1 | 1 | Centered 3 x 3 cm2 field |
| `WaterPhantom05x05` | 71 | 1 | 1 | Centered 5 x 5 cm2 field |
| `WaterPhantom10x10` | 71 | 1 | 1 | Centered 10 x 10 cm2 field |
| `WaterPhantom20x20` | 71 | 1 | 1 | Centered 20 x 20 cm2 field |

The repository currently contains 452 DICOM files (426 CT, 6 RT Plan, and 20
RT Dose files). File names intentionally omit DICOM UIDs that existed in the
source names. DICOM references are stored inside the files and do not depend on
the repository file names.

## Use with dicomxphits

Clone this repository separately from `dicomxphits`. Select a case's `CT`
directory and its `RTPLAN.dcm` in the guided Windows workflow, or pass them to
the corresponding command-line adapter. Keep generated workspaces and licensed
PHITS/RT-PHITS files outside both repositories.

Example paths:

```text
<data-root>/WaterPhantom10x10/CT/
<data-root>/WaterPhantom10x10/RTPLAN.dcm
```

Follow the current instructions and safety gates in the
[`dicomxphits` README](https://github.com/inata169/dicomxphits#readme).

## Privacy and integrity checks

Before the initial commit, all 452 files were parsed with pydicom without
reading external resources. The audit found:

- dummy identity values such as `ANONYMOUS` and synthetic phantom identifiers;
- no private DICOM elements;
- no overlay elements;
- no non-empty address, telephone, accession, operator, or device serial fields;
- all human-readable string VRs in the main dataset, nested sequences, and File
  Meta Information checked against tag-specific reviewed values or strict
  structured-value rules;
- uniform water-phantom pixels without visible burned-in text in all 71
  `PHITSgeoTest` CT slices and representative slices from the other series;
- internally consistent Study and Frame of Reference UIDs within each case;
- RT Dose references that resolve to the RT Plan in the same case.

Source instance/reference UIDs were replaced with consistent anonymous UIDs.
The remaining `InstanceCreatorUID` identifies the creating implementation's
organization root, not a patient or study instance.

This is evidence for the present files, not a guarantee for future additions.
Run the repository audit and checksum verification before every upload:

```powershell
py -3.12 -m pip install -r requirements-audit.txt
py -3.12 -m unittest discover -s tests -v
py -3.12 scripts/audit_dicom.py --check-checksums
```

The `DICOM audit` GitHub Actions workflow runs the same checksum, privacy, and
referential-integrity checks on every pull request to `main`, every push to
`main`, and manual dispatch. It uses read-only repository permissions. For a
pull request, the workflow executes the audit implementation and dependency
definition from the target branch, so changing the checker in the same pull
request cannot approve unchecked DICOM data. Merge audit-policy changes before
submitting data that depends on them.

The audit fails on known direct identifiers, private or overlay elements,
unexpected identity values, unreviewed free text or AE Titles, unknown UID
roots, broken case references, checksum mismatches, and files at or above
GitHub's 100 MiB hard limit. DICOM dates and times require tag-specific reviewed
fingerprints as well as valid VR syntax; numeric strings are checked for their
VR-specific syntax. UIDs are limited to registered DICOM standard values,
the anonymization root, and the reviewed implementation value. This applies to
nested sequences and File Meta as well as top-level tags, so newly added DICOM
files use the same fail-closed policy.

Audit failures identify the file, tag, keyword, VR, value length, and a shortened
SHA-256 fingerprint without printing the header value. Treat an unapproved value
as confidential: verify its provenance privately before changing the policy,
and never copy it into source, tests, workflow configuration, logs, README text,
or a public issue. A missing `BurnedInAnnotation` tag is reported as a warning
because these source files omit it; contributors must still inspect
representative pixels.

The coordinate-fixed derivative in `WaterPhantom-golden8` has its own SOP
Instance UID so it can be distinguished from its source beam-dose object.

See [CONTRIBUTING.md](CONTRIBUTING.md) before adding or replacing data. If you
discover possible identifying information, follow [SECURITY.md](SECURITY.md)
and do not post it in a public issue.

## Storage policy

DICOM files are marked as binary in `.gitattributes`. Git LFS is not required
for the current snapshot: the largest file is below 7 MiB and no file approaches
GitHub's 100 MiB per-file limit. Reconsider storage before adding a large new
series; do not split, archive, or rewrite DICOM solely to bypass a hosting limit.

## Data use terms

The DICOM files may be used only for non-clinical education, research, and local
workflow validation with `dicomxphits`. Redistribution or republication as a
separate dataset, unrelated general-purpose use, commercial distribution, and
clinical use are not permitted. GitHub-hosted viewing and forks remain subject
to GitHub's Terms of Service.

See [DATA_USE_TERMS.md](DATA_USE_TERMS.md) for the complete terms. No Creative
Commons, MIT, or other general-purpose open license is granted for the DICOM
files. The software in `dicomxphits` has its own license.
