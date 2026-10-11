/*
 * wal.h — Write-Ahead Log (WAL) for crash consistency
 *
 * Purpose: solve the "power loss mid-operation" problem documented early
 * in PROJECT.md (the 30-second RAM-cache gap, and flash-drive corruption
 * during transfer). Also doubles as a fast post-crash scan — instead of
 * scanning the entire repo after an unclean shutdown, we only need to
 * read the small WAL file and resolve any unfinished operations.
 *
 * Model: before a multi-step operation (e.g. repo-pack writes N chunk
 * files + 1 manifest file; repo-gc deletes multiple orphaned chunks),
 * we append a BEGIN record. Once the operation is fully done and safe,
 * we append a matching COMMIT record. Both are fsync'd before the
 * caller proceeds, so a crash can only ever leave an operation either
 * "never started" (no BEGIN) or "started but not committed" (BEGIN with
 * no matching COMMIT) — never a silently half-applied state that looks
 * valid.
 *
 * ads7_wal_check() scans for BEGIN records with no matching COMMIT and
 * repairs them (currently: discard the untrusted output of that
 * operation, since we can't prove it finished correctly).
 */

#ifndef ADS7_WAL_H
#define ADS7_WAL_H

#include <stdint.h>

typedef enum {
    ADS7_WAL_OP_PACK = 0,
    ADS7_WAL_OP_GC   = 1
} ads7_wal_op_t;

/* Appends a BEGIN record (fsync'd). target is a manifest name for PACK,
 * or may be empty/ignored for GC. Returns the sequence number to pass
 * to ads7_wal_commit, or 0 on failure. */
uint64_t ads7_wal_begin(const char *repo_dir, ads7_wal_op_t op, const char *target);

/* Appends a matching COMMIT record (fsync'd) for a previous BEGIN.
 * Returns 0 on success, -1 on failure. */
int ads7_wal_commit(const char *repo_dir, uint64_t seq);

/* Scans repo.wal for BEGIN records with no matching COMMIT, repairs
 * them (removes the untrusted manifest for an uncommitted PACK), and
 * prints a short report. Returns the number of incomplete operations
 * found and repaired (0 = repo was already consistent), or -1 on error. */
int ads7_wal_check(const char *repo_dir);

#endif
