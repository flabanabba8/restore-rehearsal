# Verification

- Seven unit tests passed, including ZIP path safety, trusted hash coverage, cleanup on mismatch and owner-only POSIX permissions for restored files under a permissive umask. Hermes plugin validation passed without warnings.
- A synthetic local PageCast recovery reopened and exported a restored book after the permission change. No production backup was modified or tested.
- Native Windows Python 3.14 restored a synthetic ZIP with an independently supplied matching hash. Windows ACL behavior and production backups were not tested.
- Older restores are not retroactively chmodded. Archive completeness without an independent manifest, full Windows coverage, a reviewed demo and the full publication audit remain unverified.
