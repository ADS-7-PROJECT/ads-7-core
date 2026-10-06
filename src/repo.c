#include "repo.h"
#include "ads7.h"
#include "crypto.h"
#include "compress.h"
#include "keymgmt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>

#define ADS7_REPO_MAGIC   0x41443744u  /* "AD7D" (Dedup) */

/* --- بنية "قائمة" الملف داخل المستودع (Manifest) ---
 * شبيهة بـ Index Core العادي، بس بدون تخزين مكان الأجزاء داخل نفس الملف —
 * كل جزء يُشار له بالـ hash فقط، والموقع الفعلي بمجلد chunks/ */
typedef struct {
    uint32_t chunk_id;
    uint64_t original_size;      /* الحجم قبل الضغط — لازم لفك الضغط لاحقاً */
    unsigned char hash[ADS7_SHA256_LEN];
} repo_chunk_ref_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t original_file_size;
    uint32_t chunk_count;
    unsigned char full_file_hash[ADS7_SHA256_LEN];
    repo_chunk_ref_t chunks[ADS7_MAX_CHUNKS];
} repo_manifest_t;

/* --- مفتاح تشفير موحّد على مستوى المستودع كله (مو لكل ملف لحاله) ---
 * هذا ضروري لـ dedup: لو كل ملف اشتق مفتاحه من salt عشوائي خاص فيه،
 * الأجزاء المشتركة بين ملفين تصير مشفرة بمفاتيح مختلفة، وفك التشفير
 * يفشل لأي ملف ثاني يحاول يعيد استخدام جزء موجود من قبل.
 * (V3: استبدلنا هذا بنظام keymgmt.c الكامل — مفتاح رئيسي عشوائي +
 * خانتين قفل، مو مجرد salt+PBKDF2 مباشر) */

static void hash_to_hex(const unsigned char hash[ADS7_SHA256_LEN], char out_hex[65])
{
    static const char *hexdigits = "0123456789abcdef";
    for (int i = 0; i < ADS7_SHA256_LEN; i++) {
        out_hex[i * 2]     = hexdigits[(hash[i] >> 4) & 0xF];
        out_hex[i * 2 + 1] = hexdigits[hash[i] & 0xF];
    }
    out_hex[64] = '\0';
}

static int ensure_dir(const char *path)
{
    if (mkdir(path, 0755) == 0) return 0;
    return (errno == EEXIST) ? 0 : -1;
}

static int ensure_repo_dirs(const char *repo_dir)
{
    char buf[1024];
    if (ensure_dir(repo_dir) != 0) return -1;
    snprintf(buf, sizeof(buf), "%s/chunks", repo_dir);
    if (ensure_dir(buf) != 0) return -1;
    snprintf(buf, sizeof(buf), "%s/manifests", repo_dir);
    if (ensure_dir(buf) != 0) return -1;
    return 0;
}

static unsigned char *read_whole_file2(const char *path, uint64_t *out_size)
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
    *out_size = (uint64_t)sz;
    return buf;
}

int ads7_repo_pack(const char *repo_dir, const char *input_path,
                    const char *manifest_name, const char *password)
{
    if (ensure_repo_dirs(repo_dir) != 0) {
        fprintf(stderr, "[repo_pack] فشل إنشاء مجلدات المستودع\n");
        return -1;
    }

    uint64_t file_size = 0;
    unsigned char *file_data = read_whole_file2(input_path, &file_size);
    if (!file_data) { fprintf(stderr, "[repo_pack] فشل قراءة الملف\n"); return -1; }

    repo_manifest_t mf;
    memset(&mf, 0, sizeof(mf));
    mf.magic = ADS7_REPO_MAGIC;
    mf.version = ADS7_VERSION;
    mf.original_file_size = file_size;
    ads7_sha256(file_data, (size_t)file_size, mf.full_file_hash);

    uint32_t chunk_count = ads7_calc_chunk_count(file_size);
    mf.chunk_count = chunk_count;

    unsigned char key[ADS7_AES_KEY_LEN]; /* المفتاح الرئيسي (master key) — عشوائي 100% */
    if (!ads7_keymgmt_exists(repo_dir)) {
        char recovery[ADS7_RECOVERY_MAX_LEN];
        if (ads7_keymgmt_init(repo_dir, password, key, recovery) != 0) {
            free(file_data); return -1;
        }
        fprintf(stdout, "\n=====================================================\n");
        fprintf(stdout, "🔑 مستودع جديد — تم توليد مفتاح رئيسي عشوائي 100%%\n");
        fprintf(stdout, "عبارة الاسترجاع (احفظها الآن بمكان آمن — ما راح تظهر مرة ثانية):\n\n");
        fprintf(stdout, "    %s\n\n", recovery);
        fprintf(stdout, "لو نسيت الباسورد، هاي العبارة تفتح المستودع بديل عنه.\n");
        fprintf(stdout, "=====================================================\n\n");
    } else {
        if (ads7_keymgmt_unlock(repo_dir, password, key) != 0) {
            fprintf(stderr, "[repo_pack] فشل فتح المستودع — باسورد غلط أو ملف مفاتيح تالف\n");
            free(file_data); return -1;
        }
    }

    uint64_t base = file_size / chunk_count;
    uint64_t rem = file_size % chunk_count;
    uint64_t cursor = 0;

    uint32_t new_chunks_written = 0, dedup_hits = 0;
    uint64_t bytes_actually_written = 0;

    for (uint32_t i = 0; i < chunk_count; i++) {
        uint64_t len = base + (i < rem ? 1 : 0);
        if (chunk_count == 1) len = file_size;

        unsigned char *chunk_ptr = file_data + cursor;

        unsigned char hash[ADS7_SHA256_LEN];
        ads7_sha256(chunk_ptr, (size_t)len, hash);

        char hex[65];
        hash_to_hex(hash, hex);
        char chunk_path[1200];
        snprintf(chunk_path, sizeof(chunk_path), "%s/chunks/%s.chunk", repo_dir, hex);

        FILE *existing = fopen(chunk_path, "rb");
        if (existing) {
            /* --- Dedup hit: نفس بصمة الجزء موجودة أصلاً بالمستودع، ما نخزن شي --- */
            fclose(existing);
            dedup_hits++;
        } else {
            /* --- جزء جديد: نضغط ونشفر ونخزنه لأول مرة --- */
            unsigned char *compressed = NULL; size_t compressed_len = 0;
            if (ads7_compress(chunk_ptr, (size_t)len, &compressed, &compressed_len) != 0) {
                free(file_data); return -1;
            }
            unsigned char iv[ADS7_AES_IV_LEN];
            ads7_random_bytes(iv, ADS7_AES_IV_LEN);

            unsigned char tag[ADS7_GCM_TAG_LEN];
            unsigned char *encrypted = NULL; size_t encrypted_len = 0;
            if (ads7_encrypt(key, iv, compressed, compressed_len, &encrypted, &encrypted_len, tag) != 0) {
                free(compressed); free(file_data); return -1;
            }
            free(compressed);

            FILE *cf = fopen(chunk_path, "wb");
            if (!cf) { free(encrypted); free(file_data); return -1; }
            fwrite(iv, 1, ADS7_AES_IV_LEN, cf);
            fwrite(tag, 1, ADS7_GCM_TAG_LEN, cf);
            fwrite(encrypted, 1, encrypted_len, cf);
            fclose(cf);

            bytes_actually_written += encrypted_len + ADS7_AES_IV_LEN + ADS7_GCM_TAG_LEN;
            free(encrypted);
            new_chunks_written++;
        }

        mf.chunks[i].chunk_id = i;
        mf.chunks[i].original_size = len;
        memcpy(mf.chunks[i].hash, hash, ADS7_SHA256_LEN);

        cursor += len;
    }
    free(file_data);

    char manifest_path[1200];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifests/%s.ads7m", repo_dir, manifest_name);
    FILE *mfile = fopen(manifest_path, "wb");
    if (!mfile) { fprintf(stderr, "[repo_pack] فشل كتابة manifest\n"); return -1; }
    fwrite(&mf, sizeof(mf), 1, mfile);
    fclose(mfile);

    fprintf(stdout, "[repo_pack] تم: %u جزء إجمالي | %u جزء جديد مخزّن | %u جزء dedup (تم توفيره) | %lu بايت كُتبت فعلياً\n",
            chunk_count, new_chunks_written, dedup_hits, (unsigned long)bytes_actually_written);
    return 0;
}

int ads7_repo_unpack(const char *repo_dir, const char *manifest_name,
                      const char *output_path, const char *password)
{
    char manifest_path[1200];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifests/%s.ads7m", repo_dir, manifest_name);

    FILE *mfile = fopen(manifest_path, "rb");
    if (!mfile) { fprintf(stderr, "[repo_unpack] manifest غير موجود: %s\n", manifest_path); return -1; }

    repo_manifest_t mf;
    if (fread(&mf, sizeof(mf), 1, mfile) != 1) { fclose(mfile); return -1; }
    fclose(mfile);

    if (mf.magic != ADS7_REPO_MAGIC) {
        fprintf(stderr, "[repo_unpack] manifest غير صالح\n");
        return -1;
    }

    unsigned char key[ADS7_AES_KEY_LEN];
    if (ads7_keymgmt_unlock(repo_dir, password, key) != 0) {
        fprintf(stderr, "[repo_unpack] فشل فتح المستودع — باسورد/عبارة استرجاع غلط\n");
        return -1;
    }

    unsigned char *assembled = malloc(mf.original_file_size > 0 ? mf.original_file_size : 1);
    if (!assembled) return -1;
    uint64_t cursor = 0;

    for (uint32_t i = 0; i < mf.chunk_count; i++) {
        char hex[65];
        hash_to_hex(mf.chunks[i].hash, hex);
        char chunk_path[1200];
        snprintf(chunk_path, sizeof(chunk_path), "%s/chunks/%s.chunk", repo_dir, hex);

        uint64_t cs = 0;
        unsigned char *raw = read_whole_file2(chunk_path, &cs);
        if (!raw || cs < (uint64_t)(ADS7_AES_IV_LEN + ADS7_GCM_TAG_LEN)) {
            fprintf(stderr, "[repo_unpack] ⚠️ جزء مفقود أو تالف بالمستودع: %s\n", hex);
            free(raw); free(assembled);
            return -2;
        }

        unsigned char iv[ADS7_AES_IV_LEN];
        memcpy(iv, raw, ADS7_AES_IV_LEN);
        unsigned char tag[ADS7_GCM_TAG_LEN];
        memcpy(tag, raw + ADS7_AES_IV_LEN, ADS7_GCM_TAG_LEN);
        unsigned char *ciphertext = raw + ADS7_AES_IV_LEN + ADS7_GCM_TAG_LEN;
        size_t ciphertext_len = (size_t)(cs - ADS7_AES_IV_LEN - ADS7_GCM_TAG_LEN);

        unsigned char *compressed = NULL; size_t compressed_len = 0;
        if (ads7_decrypt(key, iv, ciphertext, ciphertext_len, tag, &compressed, &compressed_len) != 0) {
            fprintf(stderr, "[repo_unpack] فشل فك تشفير جزء %s — بصمة توثيق GCM غير مطابقة (تلاعب/تلف)\n", hex);
            free(raw); free(assembled);
            return -1;
        }
        free(raw);

        unsigned char *original = NULL;
        if (ads7_decompress(compressed, compressed_len, (size_t)mf.chunks[i].original_size, &original) != 0) {
            fprintf(stderr, "[repo_unpack] فشل فك ضغط جزء %s\n", hex);
            free(compressed); free(assembled);
            return -1;
        }
        free(compressed);

        unsigned char check[ADS7_SHA256_LEN];
        ads7_sha256(original, (size_t)mf.chunks[i].original_size, check);
        if (memcmp(check, mf.chunks[i].hash, ADS7_SHA256_LEN) != 0) {
            fprintf(stderr, "[repo_unpack] ⚠️ تلف بجزء %s — hash غير مطابق (Parity غير مدعوم بوضع repo بعد)\n", hex);
            free(original); free(assembled);
            return -2;
        }

        memcpy(assembled + cursor, original, mf.chunks[i].original_size);
        cursor += mf.chunks[i].original_size;
        free(original);
    }

    unsigned char full_check[ADS7_SHA256_LEN];
    ads7_sha256(assembled, (size_t)mf.original_file_size, full_check);
    if (memcmp(full_check, mf.full_file_hash, ADS7_SHA256_LEN) != 0) {
        fprintf(stderr, "[repo_unpack] ⚠️ hash الملف الكامل غير مطابق!\n");
        free(assembled);
        return -2;
    }

    FILE *out = fopen(output_path, "wb");
    if (!out) { free(assembled); return -1; }
    if (mf.original_file_size > 0)
        fwrite(assembled, 1, (size_t)mf.original_file_size, out);
    fclose(out);
    free(assembled);

    fprintf(stdout, "[repo_unpack] تم بنجاح — %u جزء، تحقق كامل سليم ✅\n", mf.chunk_count);
    return 0;
}

int ads7_repo_delete(const char *repo_dir, const char *manifest_name)
{
    char manifest_path[1200];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifests/%s.ads7m", repo_dir, manifest_name);

    if (remove(manifest_path) != 0) {
        fprintf(stderr, "[repo_delete] فشل حذف manifest (موجود أصلاً؟): %s\n", manifest_path);
        return -1;
    }

    fprintf(stdout, "[repo_delete] تم حذف '%s' — ملاحظة: الأجزاء نفسها ما انحذفت (ممكن ملفات ثانية تستخدمها).\n"
                     "              شغّل 'repo-gc' عشان تحرر الأجزاء اليتيمة فعلياً.\n", manifest_name);
    return 0;
}

/* --- قائمة ديناميكية بسيطة لبصمات الأجزاء المُشار لها (hex strings) --- */
typedef struct {
    char (*items)[65];
    size_t count;
    size_t capacity;
} hex_set_t;

static void hex_set_add(hex_set_t *set, const char *hex)
{
    if (set->count == set->capacity) {
        size_t new_cap = set->capacity == 0 ? 64 : set->capacity * 2;
        set->items = realloc(set->items, new_cap * sizeof(*set->items));
        set->capacity = new_cap;
    }
    memcpy(set->items[set->count], hex, 65);
    set->count++;
}

static int hex_set_contains(const hex_set_t *set, const char *hex)
{
    for (size_t i = 0; i < set->count; i++) {
        if (strcmp(set->items[i], hex) == 0) return 1;
    }
    return 0;
}

int ads7_repo_gc(const char *repo_dir)
{
    char manifests_dir[1100];
    snprintf(manifests_dir, sizeof(manifests_dir), "%s/manifests", repo_dir);

    hex_set_t referenced;
    memset(&referenced, 0, sizeof(referenced));

    /* --- المرحلة 1: اجمع كل بصمات الأجزاء اللي لسا يشير لها أي manifest --- */
    DIR *md = opendir(manifests_dir);
    if (!md) {
        fprintf(stderr, "[repo_gc] مجلد manifests مو موجود\n");
        return -1;
    }

    uint32_t manifests_scanned = 0;
    struct dirent *ent;
    while ((ent = readdir(md)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char full[1500];
        snprintf(full, sizeof(full), "%s/%s", manifests_dir, ent->d_name);

        FILE *f = fopen(full, "rb");
        if (!f) continue;

        repo_manifest_t mf;
        if (fread(&mf, sizeof(mf), 1, f) == 1 && mf.magic == ADS7_REPO_MAGIC) {
            for (uint32_t i = 0; i < mf.chunk_count && i < ADS7_MAX_CHUNKS; i++) {
                char hex[65];
                hash_to_hex(mf.chunks[i].hash, hex);
                if (!hex_set_contains(&referenced, hex)) hex_set_add(&referenced, hex);
            }
            manifests_scanned++;
        }
        fclose(f);
    }
    closedir(md);

    /* --- المرحلة 2: افحص كل الأجزاء الموجودة فعلياً، احذف اللي مالهم manifest --- */
    char chunks_dir[1100];
    snprintf(chunks_dir, sizeof(chunks_dir), "%s/chunks", repo_dir);

    DIR *cd = opendir(chunks_dir);
    if (!cd) {
        fprintf(stderr, "[repo_gc] مجلد chunks مو موجود\n");
        free(referenced.items);
        return -1;
    }

    uint32_t removed_count = 0;
    uint64_t removed_bytes = 0;
    uint32_t kept_count = 0;

    while ((ent = readdir(cd)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        /* صيغة الاسم المتوقعة: 64 حرف hex + ".chunk" = 70 حرف بالضبط */
        size_t name_len = strlen(ent->d_name);
        if (name_len != 70) continue; /* اسم غير متوقع (ملف غريب بالمجلد)، نتجاهله بأمان */

        char hex[65];
        memcpy(hex, ent->d_name, 64);
        hex[64] = '\0';

        char full[1500];
        snprintf(full, sizeof(full), "%s/%s", chunks_dir, ent->d_name);

        if (!hex_set_contains(&referenced, hex)) {
            struct stat st;
            if (stat(full, &st) == 0) removed_bytes += (uint64_t)st.st_size;
            remove(full);
            removed_count++;
        } else {
            kept_count++;
        }
    }
    closedir(cd);
    free(referenced.items);

    fprintf(stdout, "[repo_gc] تم فحص %u manifest | %u جزء محتفظ فيه (لسا مستخدم) | "
                     "%u جزء يتيم محذوف | %lu بايت تحرّرت\n",
            manifests_scanned, kept_count, removed_count, (unsigned long)removed_bytes);
    return 0;
}


int ads7_repo_stats(const char *repo_dir)
{
    char chunks_dir[1100];
    snprintf(chunks_dir, sizeof(chunks_dir), "%s/chunks", repo_dir);

    DIR *d = opendir(chunks_dir);
    if (!d) { fprintf(stderr, "[repo_stats] المستودع مو موجود أو فاضي\n"); return -1; }

    uint32_t count = 0;
    uint64_t total_bytes = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char full[1500];
        snprintf(full, sizeof(full), "%s/%s", chunks_dir, ent->d_name);
        struct stat st;
        if (stat(full, &st) == 0) {
            count++;
            total_bytes += (uint64_t)st.st_size;
        }
    }
    closedir(d);

    printf("=== ADS-7 Repo Stats ===\n");
    printf("أجزاء فريدة مخزّنة : %u\n", count);
    printf("الحجم الفعلي بالمستودع : %lu بايت\n", (unsigned long)total_bytes);
    return 0;
}
