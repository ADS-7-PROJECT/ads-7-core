#include "ads7.h"
#include "repo.h"
#include "keymgmt.h"
#include "seal.h"
#include "parallel.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void usage(const char *prog)
{
    fprintf(stderr,
        "ADS-7 — Phase 1 Prototype CLI (V5: GCM + Parity + Dedup + Seal + GC)\n"
        "Usage:\n"
        "  %s pack   <input_file> <container.ads7> <password>\n"
        "  %s unpack <container.ads7> <output_file> <password>\n"
        "  %s inspect <container.ads7>\n"
        "  %s repo-pack   <repo_dir> <input_file> <manifest_name> <password>\n"
        "  %s repo-unpack <repo_dir> <manifest_name> <output_file> <password>\n"
        "  %s repo-stats  <repo_dir>\n"
        "  %s repo-delete <repo_dir> <manifest_name>\n"
        "  %s repo-gc     <repo_dir>\n"
        "  %s keygen\n"
        "  %s seal-init    <repo_dir>\n"
        "  %s seal-protect <repo_dir> <manifest_name>\n"
        "  %s seal-verify  <repo_dir> <manifest_name>\n"
        "  %s pack-parallel   <input_file> <container.ads7> <password> [threads]\n"
        "  %s unpack-parallel <container.ads7> <output_file> <password> [threads]\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return 1; }

    if (strcmp(argv[1], "pack") == 0) {
        if (argc != 5) { usage(argv[0]); return 1; }
        return ads7_pack(argv[2], argv[3], argv[4]) == 0 ? 0 : 1;
    }
    else if (strcmp(argv[1], "unpack") == 0) {
        if (argc != 5) { usage(argv[0]); return 1; }
        int rc = ads7_unpack(argv[2], argv[3], argv[4]);
        return rc == 0 ? 0 : 1;
    }
    else if (strcmp(argv[1], "inspect") == 0) {
        if (argc != 3) { usage(argv[0]); return 1; }
        return ads7_inspect(argv[2]) == 0 ? 0 : 1;
    }
    else if (strcmp(argv[1], "repo-pack") == 0) {
        if (argc != 6) { usage(argv[0]); return 1; }
        return ads7_repo_pack(argv[2], argv[3], argv[4], argv[5]) == 0 ? 0 : 1;
    }
    else if (strcmp(argv[1], "repo-unpack") == 0) {
        if (argc != 6) { usage(argv[0]); return 1; }
        return ads7_repo_unpack(argv[2], argv[3], argv[4], argv[5]) == 0 ? 0 : 1;
    }
    else if (strcmp(argv[1], "repo-stats") == 0) {
        if (argc != 3) { usage(argv[0]); return 1; }
        return ads7_repo_stats(argv[2]) == 0 ? 0 : 1;
    }
    else if (strcmp(argv[1], "repo-delete") == 0) {
        if (argc != 4) { usage(argv[0]); return 1; }
        return ads7_repo_delete(argv[2], argv[3]) == 0 ? 0 : 1;
    }
    else if (strcmp(argv[1], "repo-gc") == 0) {
        if (argc != 3) { usage(argv[0]); return 1; }
        return ads7_repo_gc(argv[2]) == 0 ? 0 : 1;
    }
    else if (strcmp(argv[1], "keygen") == 0) {
        char pass[128];
        if (ads7_generate_passphrase(pass, sizeof(pass)) != 0) {
            fprintf(stderr, "فشل توليد المفتاح\n");
            return 1;
        }
        printf("%s\n", pass);
        return 0;
    }
    else if (strcmp(argv[1], "seal-init") == 0) {
        if (argc != 3) { usage(argv[0]); return 1; }
        return ads7_seal_init(argv[2]) == 0 ? 0 : 1;
    }
    else if (strcmp(argv[1], "seal-protect") == 0) {
        if (argc != 4) { usage(argv[0]); return 1; }
        return ads7_seal_protect(argv[2], argv[3]) == 0 ? 0 : 1;
    }
    else if (strcmp(argv[1], "seal-verify") == 0) {
        if (argc != 4) { usage(argv[0]); return 1; }
        int rc = ads7_seal_verify(argv[2], argv[3]);
        if (rc == 0) { printf("✅ الختم صالح — المانيفست سليم ولم يتغير\n"); return 0; }
        printf("❌ الختم غير صالح — المانيفست اتغيّر أو الختم غلط\n");
        return 1;
    }

    else if (strcmp(argv[1], "pack-parallel") == 0) {
        if (argc != 5 && argc != 6) { usage(argv[0]); return 1; }
        int threads = (argc == 6) ? atoi(argv[5]) : 0;
        return ads7_pack_parallel(argv[2], argv[3], argv[4], threads) == 0 ? 0 : 1;
    }
    else if (strcmp(argv[1], "unpack-parallel") == 0) {
        if (argc != 5 && argc != 6) { usage(argv[0]); return 1; }
        int threads = (argc == 6) ? atoi(argv[5]) : 0;
        return ads7_unpack_parallel(argv[2], argv[3], argv[4], threads) == 0 ? 0 : 1;
    }

    usage(argv[0]);
    return 1;
}
