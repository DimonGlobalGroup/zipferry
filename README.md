# ZipFerry

**Audit a ZIP archive before you open it — unsafe paths, duplicates, case collisions, and expansion bombs — from its metadata alone.**

ZipFerry is a single-file, standard-library-only Python tool that
answers one question, read-only and offline:

> `audit ARCHIVE.zip` — is this archive safe to open, and what does
> it claim to contain?

It reads **only the ZIP central directory**. It never extracts,
never decompresses entry data, and never writes anything. Auditing
a suspected decompression bomb therefore costs kilobytes, not
gigabytes.

```console
$ python3 zipferry.py audit bundle.zip
archive: bundle.zip (4 entries, 4 files, 1204 bytes declared)
warning: executable-entry: run.exe [bundle.zip]
warning: nested-archive: inner.zip [bundle.zip]
zipferry: 1 archives, 4 entries, 4 files, 1204 bytes declared, 0 errors, 2 warnings
```

## Why this exists

Extraction tools and malware scanners answer their questions *while*
or *after* opening an archive. The failures that hurt are visible
beforehand, in the metadata:

- **Zip Slip paths** (`../evil`, absolute paths, drive letters,
  backslashes) that a careless extractor writes outside the folder
  you chose.
- **Duplicate entries** — a later entry silently overwriting an
  earlier one of the same name.
- **Case collisions** (`Photo.jpg` next to `photo.jpg`) that lose a
  file the moment the set lands on a case-insensitive filesystem.
- **Expansion bombs** — declared sizes and compression ratios that
  announce a bomb before a single byte is decompressed.
- **Symlinks and encrypted entries**, whose contents metadata
  cannot vouch for — flagged, never trusted silently.
- **The entry list itself can be private.** With
  `--fingerprint-only`, reports identify entries by position and
  CRC-32 fingerprint — no entry name ever appears, in text or JSON
  output. That is enforced by tests with canary entry names, not
  just promised here.

ZipFerry is a gate, not an extractor: it never writes, extracts,
decompresses, or executes anything, and it never opens the network.
The extract decision stays with the human.

## Install

Nothing to install. Python 3.10 or newer, standard library only:

```console
$ python3 zipferry.py --version
zipferry 1.0.0
```

## Usage

```console
python3 zipferry.py audit ARCHIVE.zip [ARCHIVE.zip ...] [--json] [--max-examples N] [--fingerprint-only] [--max-ratio N] [--max-total BYTES] [--max-entries N]
```

Defaults: `--max-ratio 100`, `--max-total 1073741824` (1 GiB of
declared output), `--max-entries 10000`, `--max-examples 10`
per finding code; totals are always exact and suppressed examples
are counted.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No error findings (warnings may be present) |
| 1 | Error findings present (unsafe paths, duplicates, case collisions, ratio/size/entry ceilings, …) |
| 2 | Usage or I/O error (missing file, not a ZIP, bad options) |

Errors: `unsafe-path`, `duplicate-entry`, `case-collision`,
`high-ratio`, `total-size`, `too-many-entries`.
Warnings: `symlink`, `encrypted-entry`, `empty-file`,
`executable-entry`, `nested-archive`.

## Limitations, honestly

- **Declared sizes are untrusted metadata.** A forged archive can
  understate its entries' true sizes; ZipFerry reports what the
  central directory claims and flags what is implausible on its
  face. It is a triage gate, not a proof — extract anything
  consequential inside a resource-limited sandbox.
- ZipFerry does not scan contents for malware and does not replace
  an antivirus or a sandboxed extractor.
- Only ZIP is supported. Other archive formats (tar, 7z, rar) are
  out of scope for this single-file tool.
- CRC fingerprints identify entries for reporting; a CRC-32 is not
  a cryptographic hash and proves nothing about content.

## License

MIT — see `LICENSE`. Copyright (c) 2026 Dimon Global Group.
