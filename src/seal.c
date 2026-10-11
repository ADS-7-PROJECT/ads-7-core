#include "seal.h"
#include "ads7.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define SEAL_SECRET_LEN 32
#define HMAC_OUT_LEN    32

static int ensure_dir2(const char *path)
{
    if (mkdir(path, 0755) == 0) return 0;
    return 0; /* EEXIST أو غيره — نكمل، فحص الوجود الفعلي يصير بالقراءة بعدها */
}

static int read_file_bytes(const char *path, unsigned char *buf, size_t expect_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t r = fread(buf, 1, expect_len, f);
    fclose(f);
    return (r == expect_len) ? 0 : -1;
}

static unsigned char *read_whole_for_seal(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    unsigned char *buf = malloc((size_t)sz > 0 ? (size_t)sz : 1);
    if (!buf) { fclose(f); return NULL; }
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

static void root_key_path(const char *repo_dir, char *out, size_t out_sz)
{
    snprintf(out, out_sz, "%s/.seal_root.key", repo_dir);
}
static void manifest_file_path(const char *repo_dir, const char *name, char *out, size_t out_sz)
{
    snprintf(out, out_sz, "%s/manifests/%s.ads7m", repo_dir, name);
}
static void seal_file_path(const char *repo_dir, const char *name, char *out, size_t out_sz)
{
    snprintf(out, out_sz, "%s/manifests/%s.seal", repo_dir, name);
}

int ads7_seal_init(const char *repo_dir)
{
    ensure_dir2(repo_dir);
    char path[1200];
    root_key_path(repo_dir, path, sizeof(path));

    unsigned char probe[SEAL_SECRET_LEN];
    if (read_file_bytes(path, probe, SEAL_SECRET_LEN) == 0) {
        fprintf(stdout, "[seal_init] الختم الأساسي موجود أصلاً لهذا المستودع — ما سويت شي جديد\n");
        return 0; /* موجود أصلاً */
    }

    unsigned char secret[SEAL_SECRET_LEN];
    if (RAND_bytes(secret, SEAL_SECRET_LEN) != 1) return -1;

    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(secret, 1, SEAL_SECRET_LEN, f);
    fclose(f);
    chmod(path, 0600); /* قراءة/كتابة لصاحب الملف بس — تقليل السطح المكشوف */

    fprintf(stdout, "[seal_init] ✅ تم إنشاء الختم الأساسي لهذا المستودع (%s)\n", path);
    return 0;
}

static int load_root_secret(const char *repo_dir, unsigned char out[SEAL_SECRET_LEN])
{
    char path[1200];
    root_key_path(repo_dir, path, sizeof(path));
    if (read_file_bytes(path, out, SEAL_SECRET_LEN) != 0) {
        fprintf(stderr, "[seal] لا يوجد ختم أساسي بهذا المستودع — استخدم ads7_seal_init أول\n");
        return -1;
    }
    return 0;
}

int ads7_seal_protect(const char *repo_dir, const char *manifest_name)
{
    unsigned char secret[SEAL_SECRET_LEN];
    if (load_root_secret(repo_dir, secret) != 0) return -1;

    char mpath[1200];
    manifest_file_path(repo_dir, manifest_name, mpath, sizeof(mpath));

    size_t content_len = 0;
    unsigned char *content = read_whole_for_seal(mpath, &content_len);
    if (!content) {
        fprintf(stderr, "[seal_protect] manifest غير موجود: %s\n", mpath);
        return -1;
    }

    unsigned char mac[HMAC_OUT_LEN];
    unsigned int mac_len = 0;
    HMAC(EVP_sha256(), secret, SEAL_SECRET_LEN, content, content_len, mac, &mac_len);
    free(content);

    char spath[1200];
    seal_file_path(repo_dir, manifest_name, spath, sizeof(spath));
    FILE *sf = fopen(spath, "wb");
    if (!sf) return -1;
    fwrite(mac, 1, mac_len, sf);
    fclose(sf);

    fprintf(stdout, "[seal_protect] ✅ '%s' صار ضمن المنطقة المحجوزة — أي كتابة بدون الختم الصحيح تُرفض\n",
            manifest_name);
    return 0;
}

int ads7_seal_is_protected(const char *repo_dir, const char *manifest_name)
{
    char spath[1200];
    seal_file_path(repo_dir, manifest_name, spath, sizeof(spath));
    FILE *f = fopen(spath, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

int ads7_seal_verify(const char *repo_dir, const char *manifest_name)
{
    if (!ads7_seal_is_protected(repo_dir, manifest_name)) return 0; /* غير محمي أصلاً = يعدّي */

    unsigned char secret[SEAL_SECRET_LEN];
    if (load_root_secret(repo_dir, secret) != 0) return -1;

    char mpath[1200];
    manifest_file_path(repo_dir, manifest_name, mpath, sizeof(mpath));
    size_t content_len = 0;
    unsigned char *content = read_whole_for_seal(mpath, &content_len);
    if (!content) return -1; /* المانيفست نفسه مفقود */

    unsigned char mac[HMAC_OUT_LEN];
    unsigned int mac_len = 0;
    HMAC(EVP_sha256(), secret, SEAL_SECRET_LEN, content, content_len, mac, &mac_len);
    free(content);

    char spath[1200];
    seal_file_path(repo_dir, manifest_name, spath, sizeof(spath));
    unsigned char stored[HMAC_OUT_LEN];
    if (read_file_bytes(spath, stored, HMAC_OUT_LEN) != 0) return -1;

    return (memcmp(mac, stored, HMAC_OUT_LEN) == 0) ? 0 : -1;
}
