# Claude Code Guidelines

## Commit messages
- Do not add `Co-Authored-By` lines to commit messages.

## Keeping documentation in sync
- Whenever a protection check is added, removed, or reordered in `debuggerChecks[]` (in `antidebug/adbg.c`), two things must also be updated:
  1. The check list in `README.md` (0-based indices matching the array order, names matching `functionName` strings)
  2. The `-p` flag validation bounds in `parse_protection_spec()` — these are derived from `NUM_DEBUG_CHECKS` automatically, but verify the count is still correct.
