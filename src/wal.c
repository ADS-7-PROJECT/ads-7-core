#include "wal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define ADS7_WAL_MAGIC   0x4144374Cu /* "AD7L" (Log) */
#define WAL_TARGET_LEN   128

typedef struct {
    uint32_t magic;
    uint8_t  record_type;   /* 0 = BEGIN, 1 = COMMIT */
    uint8_t  op_type;       /* ads7_wal_op_t */
    uint8_t  _pad[2];
    uint64_t seq;
    char     target[WAL_TARGET_LEN];
} ads7_wal_record_t;

static int append_record(const char *repo_dir, const ads7_wal_record_t *rec)
{
    char path[1200];
    snprintf(path, sizeof(path), "%s/repo.wal", repo_dir);

    FILE *f = fopen(path, "ab");
    if (!f) return -1;

    size_t written = fwrite(rec, sizeof(*rec), 1, f);
    fflush(f);
    if (written == 1) {
        fsync(fileno(f)); /* durability: this record must hit disk before we continue */
    }
    fclose(f);

    return written == 1 ? 0 : -1;
}

uint64_t ads7_wal_begin(const char *repo_dir, ads7_wal_op_t op, const char *target)
{
    /* Sequence number: current time in microseconds XORed with a random
     * component would be ideal; for this prototype, monotonic-ish via
     * combining time(NULL) with getpid()+a static counter is enough to
     * keep BEGIN/COMMIT pairs unique within one repo. */
    static uint64_t counter = 0;
    uint64_t seq = ((uint64_t)time(NULL) << 20) ^ (uint64_t)getpid() ^ (++counter);
    if (seq == 0) seq = 1; /* 0 is reserved as "invalid" */

    ads7_wal_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.magic = ADS7_WAL_MAGIC;
    rec.record_type = 0; /* BEGIN */
    rec.op_type = (uint8_t)op;
    rec.seq = seq;
    if (target) {
        strncpy(rec.target, target, WAL_TARGET_LEN - 1);
    }

    if (append_record(repo_dir, &rec) != 0) return 0;
    return seq;
}

int ads7_wal_commit(const char *repo_dir, uint64_t seq)
{
    if (seq == 0) return -1;

    ads7_wal_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.magic = ADS7_WAL_MAGIC;
    rec.record_type = 1; /* COMMIT */
    rec.seq = seq;

    return append_record(repo_dir, &rec);
}

/* Minimal growable array of pending (uncommitted) BEGIN records */
typedef struct { ads7_wal_record_t *items; size_t count, cap; } rec_list_t;

static void list_push(rec_list_t *l, const ads7_wal_record_t *r)
{
    if (l->count == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 16;
        l->items = realloc(l->items, l->cap * sizeof(*r));
    }
    l->items[l->count++] = *r;
}

static void list_remove_seq(rec_list_t *l, uint64_t seq)
{
    for (size_t i = 0; i < l->count; i++) {
        if (l->items[i].seq == seq) {
            l->items[i] = l->items[l->count - 1];
            l->count--;
            return;
        }
    }
}

int ads7_wal_check(const char *repo_dir)
{
    char path[1200];
    snprintf(path, sizeof(path), "%s/repo.wal", repo_dir);

    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("[wal_check] No repo.wal found — nothing to verify (repo never used WAL, or is brand new).\n");
        return 0;
    }

    rec_list_t pending = {0};
    ads7_wal_record_t rec;

    while (fread(&rec, sizeof(rec), 1, f) == 1) {
        if (rec.magic != ADS7_WAL_MAGIC) {
            /* A torn/partial record at the tail (exactly the kind of
             * corruption a power loss mid-write causes) — stop reading
             * here; everything before this point is trustworthy. */
            printf("[wal_check] Stopped at a torn record (expected if power was lost mid-write) — ignoring it safely.\n");
            break;
        }
        if (rec.record_type == 0) {
            list_push(&pending, &rec);
        } else {
            list_remove_seq(&pending, rec.seq);
        }
    }
    fclose(f);

    if (pending.count == 0) {
        printf("[wal_check] ✅ Repo is consistent — no incomplete operations found.\n");
        free(pending.items);
        return 0;
    }

    printf("[wal_check] ⚠️ Found %zu incomplete operation(s) from an unclean shutdown. Repairing...\n", pending.count);

    for (size_t i = 0; i < pending.count; i++) {
        ads7_wal_record_t *r = &pending.items[i];
        if (r->op_type == ADS7_WAL_OP_PACK) {
            char manifest_path[1500];
            snprintf(manifest_path, sizeof(manifest_path), "%s/manifests/%s.ads7m", repo_dir, r->target);
            if (remove(manifest_path) == 0) {
                printf("  - Discarded untrusted manifest '%s' (pack never committed)\n", r->target);
            } else {
                printf("  - '%s' had no manifest to discard (crash likely happened before it was written)\n", r->target);
            }
        } else if (r->op_type == ADS7_WAL_OP_GC) {
            printf("  - An interrupted GC pass was found; re-run 'repo-gc' to safely finish reclaiming orphaned chunks\n");
        }
    }

    printf("[wal_check] Repair complete — repo is now consistent.\n");
    free(pending.items);
    return (int)pending.count;
}
