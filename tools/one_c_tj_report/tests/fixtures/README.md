# Saved producer fixture

`current/` contains frozen outputs of analyzer **1.6.1** (schema **1.6**) and
derive_slices **1.8.0** (schema **1.8**), generated from synthetic records for
PDF regression checks. Physical source locations are normalized to relative
`synthetic-input/...` paths before committing the snapshot. These outputs are
independent of the PDF schema profile. Tests neither parse journals nor invoke
analytical builders.

The three measurements contain A/User, A/Other, B/User and Untargeted/User.
A has a business-approved T=3 seconds, B an engineering-proposal T=2 seconds;
Untargeted has no T. Rules cover average duration >5 seconds and APDEX deficit
>0.1 with minimum N=1. A disappears in the last measurement, while B first
slows down and then returns below the threshold. All 26 slices are included.
These are artificial diagnostic settings, not default report settings or SLA.

For repository portability, `analysis.sqlite` is stored as `analysis.sqlite.bin`;
tests copy it to a temporary directory and restore its original name before
loading. The manifest hash for `analysis.sqlite` describes those renamed bytes.
`.gitattributes` disables line-ending conversion for the snapshot: CSV/JSON
hashes cover exact bytes. Embedded source locations are synthetic provenance
strings and must never be opened.

Keep the snapshot fixed when changing PDF code. Replacing it requires an
independent producer run and review; changing expected metadata to match PDF
assumptions would defeat this compatibility check.
