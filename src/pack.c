/*
 * pack.c — دورة الكتابة الكاملة:
 * فحص الحجم → ضغط (LZ4) → تشفير (AES-256) → تقسيم (7-56) → توليد hash → كتابة الحاوية
 *
 * صيغة ملف الحاوية (.ads7) بهذا النموذج الأولي:
 *   [ads7_index_core_t]  (حجم ثابت — يُكتب أولاً)
 *   [بيانات الجزء 0 المشفرة][بيانات الجزء 1 المشفرة]...[بيانات الجزء n-1]
 *
 * ملاحظة: هذا تبسيط متعمد لـ Phase 1 — الـ Index Core هنا مركزي وواحد
 * بنفس ملف الحاوية، مو موزع كسلسلة نسخ (Smart Index chain) متل التصميم
 * النهائي المتفق عليه بـ PROJECT.md. توزيع النسخ سيُضاف بمرحلة لاحقة
 * بعد ما يثبت المنطق الأساسي هنا.
 */

#include "ads7.h"
#include "crypto.h"
#include "compress.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *read_whole_file(const char *path, uint64_t *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }

    unsigned char *buf = malloc((size_t)sz > 0 ? (size_t)sz : 1);
    if (!buf) { fclose(f); return NULL; }

    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *out_size = (uint64_t)sz;
    return buf;
}

int ads7_pack(const char *input_path, const char *container_path, const char *password)
{
    uint64_t file_size = 0;
    unsigned char *file_data = read_whole_file(input_path, &file_size);
    if (!file_data) {
        fprintf(stderr, "[ads7_pack] فشل قراءة الملف: %s\n", input_path);
        return -1;
    }

    ads7_index_core_t index;
    memset(&index, 0, sizeof(index));
    index.magic = ADS7_MAGIC;
    index.version = ADS7_VERSION;
    index.original_file_size = file_size;

    ads7_sha256(file_data, (size_t)file_size, index.full_file_hash);

    uint32_t chunk_count = ads7_calc_chunk_count(file_size);
    index.chunk_count = chunk_count;
    index.is_single_extent = (chunk_count == 1) ? 1 : 0;

    if (ads7_random_bytes(index.salt, ADS7_SALT_LEN) != 0) {
        fprintf(stderr, "[ads7_pack] فشل توليد salt عشوائي\n");
        free(file_data);
        return -1;
    }

    unsigned char key[ADS7_AES_KEY_LEN];
    if (ads7_derive_key(password, index.salt, key) != 0) {
        fprintf(stderr, "[ads7_pack] فشل اشتقاق مفتاح التشفير\n");
        free(file_data);
        return -1;
    }

    FILE *out = fopen(container_path, "wb+");
    if (!out) {
        fprintf(stderr, "[ads7_pack] فشل إنشاء ملف الحاوية: %s\n", container_path);
        free(file_data);
        return -1;
    }

    /* نحجز مكان الهيدر الآن ونكتبه فعلياً بالنهاية بعد ما نعرف كل الأوفستات */
    if (fseek(out, sizeof(ads7_index_core_t), SEEK_SET) != 0) goto fail_io;

    uint64_t base_chunk_size = file_size / chunk_count;
    uint64_t remainder = file_size % chunk_count;
    uint64_t cursor = 0;
    uint64_t container_offset = sizeof(ads7_index_core_t);

    for (uint32_t i = 0; i < chunk_count; i++) {
        uint64_t this_chunk_len = base_chunk_size + (i < remainder ? 1 : 0);
        if (chunk_count == 1) this_chunk_len = file_size; /* Single Extent */

        unsigned char *chunk_ptr = file_data + cursor;

        /* بصمة الجزء الأصلي (قبل الضغط) — تُستخدم للتحقق عند القراءة */
        ads7_chunk_desc_t *desc = &index.chunks[i];
        ads7_sha256(chunk_ptr, (size_t)this_chunk_len, desc->hash);

        /* 1) ضغط */
        unsigned char *compressed = NULL;
        size_t compressed_len = 0;
        if (ads7_compress(chunk_ptr, (size_t)this_chunk_len, &compressed, &compressed_len) != 0) {
            fprintf(stderr, "[ads7_pack] فشل ضغط الجزء %u\n", i);
            goto fail_io;
        }

        /* 2) تشفير — IV فريد لكل جزء */
        unsigned char iv[ADS7_AES_IV_LEN];
        if (ads7_random_bytes(iv, ADS7_AES_IV_LEN) != 0) {
            free(compressed);
            goto fail_io;
        }
        memcpy(desc->iv, iv, ADS7_AES_IV_LEN);

        unsigned char *encrypted = NULL;
        size_t encrypted_len = 0;
        int rc = ads7_encrypt(key, iv, compressed, compressed_len, &encrypted, &encrypted_len, desc->tag);
        free(compressed);
        if (rc != 0) {
            fprintf(stderr, "[ads7_pack] فشل تشفير الجزء %u\n", i);
            goto fail_io;
        }

        /* 3) كتابة الجزء بالحاوية */
        desc->chunk_id = i;
        desc->offset_in_container = container_offset;
        desc->original_size = this_chunk_len;
        desc->compressed_size = compressed_len;
        desc->encrypted_size = encrypted_len;

        if (fwrite(encrypted, 1, encrypted_len, out) != encrypted_len) {
            free(encrypted);
            goto fail_io;
        }
        free(encrypted);

        container_offset += encrypted_len;
        cursor += this_chunk_len;
    }

    /* --- V2: توليد Parity Block (XOR لكل الأجزاء المشفرة) ---
     * هذا يخلي النظام يقدر يعيد بناء جزء واحد تالف رياضياً بدون ما يحتاج نسخة
     * باكب كاملة له — أول تطبيق حقيقي لدرع الحماية (Parity Blocks) بالتصميم.
     */
    uint64_t max_encrypted_len = 0;
    for (uint32_t i = 0; i < chunk_count; i++) {
        if (index.chunks[i].encrypted_size > max_encrypted_len)
            max_encrypted_len = index.chunks[i].encrypted_size;
    }

    unsigned char *parity_buf = calloc(1, max_encrypted_len);
    if (!parity_buf) goto fail_io;

    unsigned char *tmp_chunk = malloc(max_encrypted_len);
    if (!tmp_chunk) { free(parity_buf); goto fail_io; }

    for (uint32_t i = 0; i < chunk_count; i++) {
        ads7_chunk_desc_t *d = &index.chunks[i];
        memset(tmp_chunk, 0, max_encrypted_len);

        if (fseek(out, (long)d->offset_in_container, SEEK_SET) != 0 ||
            fread(tmp_chunk, 1, d->encrypted_size, out) != d->encrypted_size) {
            free(parity_buf); free(tmp_chunk); goto fail_io;
        }
        for (uint64_t b = 0; b < max_encrypted_len; b++) {
            parity_buf[b] ^= tmp_chunk[b];
        }
    }
    free(tmp_chunk);

    if (fseek(out, 0, SEEK_END) != 0) { free(parity_buf); goto fail_io; }
    index.parity_offset = container_offset; /* = نهاية آخر جزء مكتوب */
    index.parity_len = max_encrypted_len;
    index.has_parity = 1;

    if (fwrite(parity_buf, 1, max_encrypted_len, out) != max_encrypted_len) {
        free(parity_buf); goto fail_io;
    }
    free(parity_buf);

    /* نرجع نكتب الهيدر الكامل (بعد ما عرفنا كل الأوفستات والبصمات والـ parity) */
    if (fseek(out, 0, SEEK_SET) != 0) goto fail_io;
    if (fwrite(&index, sizeof(index), 1, out) != 1) goto fail_io;

    fclose(out);
    free(file_data);

    fprintf(stdout, "[ads7_pack] تم بنجاح: %u جزء، %s\n",
            chunk_count, index.is_single_extent ? "Single Extent (ملف صغير)" : "Adaptive Striping");
    return 0;

fail_io:
    fprintf(stderr, "[ads7_pack] خطأ كتابة/قراءة\n");
    fclose(out);
    free(file_data);
    return -1;
}
