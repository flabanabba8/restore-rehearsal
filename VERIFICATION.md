# Verification

- Mixed-case protected-directory fixtures passed on Linux and native Windows; no real credentials were used. This is not a full platform or publication audit.

- Eight unit tests passed, including ZIP path safety, trusted hash coverage, cleanup on mismatch and owner-only POSIX permissions for restored files under a permissive umask. Hermes plugin validation passed without warnings.
- A synthetic local PageCast recovery reopened and exported a restored book after the permission change. No production backup was modified or tested.
- Native Windows Python 3.14 restored a synthetic ZIP with an independently supplied matching hash. Windows ACL behavior and production backups were not tested.
- Older restores are not retroactively chmodded. Archive completeness without an independent manifest, full Windows coverage, a reviewed demo and the full publication audit remain unverified.
- 2026-11-07: real-input trial through Hermes's tool registry in a disposable profile. restore_inspect listed the 11 files of a real zip with sizes and CRCs and returned a fingerprint; restore_rehearse restored it to a private folder and returned per-file SHA-256 values. Found: only ZIP archives are supported (a tar.gz is refused with 'File is not a zip file') and an archive containing ../ paths is correctly refused as unsafe.
- 2026-11-07: tar support (plain, gzip, bzip2, xz) added after the real-input trial showed a tar.gz was refused. Tar members must be regular files or directories with plain relative names; symlinks, hard links, devices, FIFOs, absolute or .. paths, case collisions and over-limit archives are refused before anything is written; CRC is not available so crc_verified is false for tar. 11 tests (3 new tar tests) pass; a truncated tar.gz returns a clean error.
