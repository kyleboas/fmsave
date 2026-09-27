# Security scope

This fork hardens upstream fmsave 0.4.5. It is intended for local analysis of your own
Football Manager saves, not an Internet-facing upload service. It has not received a
complete independent security audit. The original MIT license and attribution remain.

## Changes

- Unlisted regions are read one compressed frame at a time, rather than loading every
  compressed frame into memory before checking decompressed sizes.
- Listed and unlisted frames have a compressed-input size cap. Decompression also uses
  the smaller of the per-frame output cap and the remaining region output budget.
- Each lazy frame read rechecks the file fingerprint and closes its file handle before
  returning data to the caller.
- Save paths are made absolute on opening, so a later working-directory change cannot
  redirect lazy reads.
- Every CSV writer prefixes formula-like text with an apostrophe. This includes headers,
  selected columns, joined sequence cells, common leading whitespace/control characters,
  and full-width formula-prefix characters. Actual numeric values are unchanged.
  JSON and JSON Lines preserve the original text.

## Limits

The default internal caps remain large enough for game saves: 1 GiB decompressed per
frame, 1 GiB plus 1 MiB compressed per frame, and 4 GiB decompressed for directory entries
plus an unlisted region. These are data-size checks, not a process memory or CPU limit.
Frame indexes, decoding, cached records, and the decompressor itself also use memory.
The total check is per region, not a cumulative budget across every reader or region.

Do not parse third-party saves in a privileged process. If you must handle untrusted
files, use an isolated process with operating-system memory, CPU, and time limits, no
network access, and only the required read-only inputs. This fork does not supply that
sandbox or guarantee that every malformed input is cheap to reject.

CSV formula protection reduces a spreadsheet-import risk; it does not make arbitrary
CSV safe in every spreadsheet and import mode. Editing, re-saving, or importing while
stripping apostrophes can undo the protection. Use JSON for exact data exchange, and do
not enable external content or formulas from untrusted sources.

Never share a real save file in an issue. For a suspected security issue, provide a
minimal synthetic reproducer without personal data or credentials. Use GitHub private
vulnerability reporting if enabled; otherwise contact the fork owner privately before
posting exploit details publicly.
