/*
 * unpack.c — دورة القراءة + التحقق من السلامة + الشفاء الذاتي (V2 مع GCM):
 * قراءة Index Core → لكل جزء: قراءة → فك تشفير (AES-256-GCM، يتحقق تلقائياً
 * من بصمة التوثيق) → فك ضغط → تحقق hash إضافي → تجميع → تحقق hash الملف الكامل
 *
 * ⚠️ فرق مهم عن نسخة CBC القديمة: مع GCM، أي تلاعب أو تلف بالبيانات المشفرة
 * يخلي عملية فك التشفير نفسها **تفشل فوراً** (بصمة التوثيق ما تطابق)، بدل ما
 * "تفك" بيانات فاسدة بصمت ونكتشف التلف بس لاحقاً عبر مقارنة hash يدوية.
 * هذا أقوى أمنياً — فأي فشل فك تشفير الآن يُعامل كـ"تلف محتمل" ويُحاول
 * الشفاء الذاتي عبر Parity، بالضبط متل فشل الـ hash القديم.
 */

#include "ads7.h"
#include "crypto.h"
#include "compress.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* يحاول إعادة بناء جزء تالف (i) من الـ Parity Block، يفك تشفيره، يتحقق من
 * الـ hash، ولو نجح يصلحه فعلياً على القرص. يرجع NULL لو فشلت إعادة البناء. */
static unsigned char *attempt_parity_heal(FILE *in, const char *container_path,
                                           ads7_index_core_t *index, uint32_t i,
                                           const unsigned char *key)
{
    ads7_chunk_desc_t *desc = &index->chunks[i];

    if (!index->has_parity) {
        fprintf(stderr, "  (لا يوجد Parity بهذه الحاوية — تم إنشاؤها بنسخة أقدم)\n");
        return NULL;
    }

    fprintf(stderr, "  → محاولة إعادة البناء من Parity Block...\n");

    unsigned char *recon = malloc(index->parity_len);
    unsigned char *tmp = malloc(index->parity_len);
    if (!recon || !tmp) { free(recon); free(tmp); return NULL; }

    if (fseek(in, (long)index->parity_offset, SEEK_SET) != 0 ||
        fread(recon, 1, index->parity_len, in) != index->parity_len) {
        fprintf(stderr, "  ⚠️ فشل قراءة Parity Block نفسه — تلف أعمق مما نقدر نعالجه بـ V2\n");
        free(recon); free(tmp);
        return NULL;
    }

    int recon_ok = 1;
    for (uint32_t j = 0; j < index->chunk_count && recon_ok; j++) {
        if (j == i) continue;
        ads7_chunk_desc_t *dj = &index->chunks[j];
        memset(tmp, 0, index->parity_len);
        if (fseek(in, (long)dj->offset_in_container, SEEK_SET) != 0 ||
            fread(tmp, 1, dj->encrypted_size, in) != dj->encrypted_size) {
            recon_ok = 0; break;
        }
        for (uint64_t b = 0; b < index->parity_len; b++) recon[b] ^= tmp[b];
    }
    free(tmp);

    if (!recon_ok) {
        fprintf(stderr, "  ⚠️ فشل إعادة البناء — أكثر من جزء تالف (Parity أحادي التحمل بس)\n");
        free(recon);
        return NULL;
    }

    unsigned char *recon_compressed = NULL; size_t recon_compressed_len = 0;
    unsigned char *recon_original = NULL;
    if (ads7_decrypt(key, desc->iv, recon, desc->encrypted_size, desc->tag,
                      &recon_compressed, &recon_compressed_len) != 0 ||
        ads7_decompress(recon_compressed, recon_compressed_len,
                         (size_t)desc->original_size, &recon_original) != 0) {
        fprintf(stderr, "  ⚠️ إعادة البناء فشلت (تلف بأكثر من جزء) — Parity أحادي التحمل\n");
        free(recon); free(recon_compressed);
        return NULL;
    }
    free(recon_compressed);

    unsigned char recon_hash[ADS7_SHA256_LEN];
    ads7_sha256(recon_original, (size_t)desc->original_size, recon_hash);
    if (memcmp(recon_hash, desc->hash, ADS7_SHA256_LEN) != 0) {
        fprintf(stderr, "  ⚠️ إعادة البناء ما طابقت الـ hash الأصلي — تلف بأكثر من جزء\n");
        free(recon); free(recon_original);
        return NULL;
    }

    fprintf(stderr, "  ✅ تم الشفاء الذاتي بنجاح عبر Parity — إصلاح الجزء %u على القرص\n", i);
    FILE *fix = fopen(container_path, "r+b");
    if (fix) {
        if (fseek(fix, (long)desc->offset_in_container, SEEK_SET) == 0) {
            fwrite(recon, 1, desc->encrypted_size, fix);
        }
        fclose(fix);
    } else {
        fprintf(stderr, "  ⚠️ الشفاء نجح بالذاكرة بس فشل الكتابة الدائمة على القرص (صلاحيات؟)\n");
    }
    free(recon);
    return recon_original;
}

int ads7_unpack(const char *container_path, const char *output_path, const char *password)
{
    FILE *in = fopen(container_path, "rb");
    if (!in) {
        fprintf(stderr, "[ads7_unpack] فشل فتح الحاوية: %s\n", container_path);
        return -1;
    }

    ads7_index_core_t index;
    if (fread(&index, sizeof(index), 1, in) != 1) {
        fprintf(stderr, "[ads7_unpack] فشل قراءة Index Core\n");
        fclose(in);
        return -1;
    }

    if (index.magic != ADS7_MAGIC) {
        fprintf(stderr, "[ads7_unpack] الملف مو حاوية ADS-7 صالحة (magic غير مطابق)\n");
        fclose(in);
        return -1;
    }
    if (index.version != ADS7_VERSION) {
        fprintf(stderr, "[ads7_unpack] إصدار غير مدعوم: %u\n", index.version);
        fclose(in);
        return -1;
    }

    unsigned char key[ADS7_AES_KEY_LEN];
    if (ads7_derive_key(password, index.salt, key) != 0) {
        fprintf(stderr, "[ads7_unpack] فشل اشتقاق مفتاح التشفير\n");
        fclose(in);
        return -1;
    }

    unsigned char *assembled = malloc(index.original_file_size > 0 ? index.original_file_size : 1);
    if (!assembled) { fclose(in); return -1; }

    uint64_t cursor = 0;

    for (uint32_t i = 0; i < index.chunk_count; i++) {
        ads7_chunk_desc_t *desc = &index.chunks[i];

        unsigned char *ciphertext = malloc(desc->encrypted_size > 0 ? desc->encrypted_size : 1);
        if (!ciphertext) { free(assembled); fclose(in); return -1; }

        if (fseek(in, (long)desc->offset_in_container, SEEK_SET) != 0 ||
            fread(ciphertext, 1, desc->encrypted_size, in) != desc->encrypted_size) {
            fprintf(stderr, "[ads7_unpack] فشل قراءة الجزء %u — ⚠️ تلف محتمل بالحاوية\n", i);
            free(ciphertext); free(assembled); fclose(in);
            return -1;
        }

        unsigned char *original = NULL;
        unsigned char *compressed = NULL;
        size_t compressed_len = 0;

        int decrypt_ok = (ads7_decrypt(key, desc->iv, ciphertext, desc->encrypted_size,
                                        desc->tag, &compressed, &compressed_len) == 0);
        free(ciphertext);

        int hash_ok = 0;
        if (decrypt_ok) {
            if (ads7_decompress(compressed, compressed_len, (size_t)desc->original_size, &original) == 0) {
                unsigned char check_hash[ADS7_SHA256_LEN];
                ads7_sha256(original, (size_t)desc->original_size, check_hash);
                hash_ok = (memcmp(check_hash, desc->hash, ADS7_SHA256_LEN) == 0);
            }
            free(compressed);
        }

        if (!decrypt_ok) {
            fprintf(stderr, "[ads7_unpack] ⚠️ فشل فك التشفير بالجزء %u — بصمة التوثيق (GCM) غير مطابقة (تلاعب/تلف)!\n", i);
        } else if (!hash_ok) {
            fprintf(stderr, "[ads7_unpack] ⚠️ تلف مكتشف بالجزء %u — الـ hash غير مطابق!\n", i);
            free(original);
        }

        if (!decrypt_ok || !hash_ok) {
            original = attempt_parity_heal(in, container_path, &index, i, key);
            if (!original) {
                free(assembled); fclose(in);
                return -2; /* تلف مكتشف، مو قابل للإصلاح بهذه النسخة */
            }
        }

        memcpy(assembled + cursor, original, desc->original_size);
        cursor += desc->original_size;
        free(original);
    }

    fclose(in);

    unsigned char full_check[ADS7_SHA256_LEN];
    ads7_sha256(assembled, (size_t)index.original_file_size, full_check);
    if (memcmp(full_check, index.full_file_hash, ADS7_SHA256_LEN) != 0) {
        fprintf(stderr, "[ads7_unpack] ⚠️ hash الملف الكامل غير مطابق بعد التجميع!\n");
        free(assembled);
        return -2;
    }

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        fprintf(stderr, "[ads7_unpack] فشل إنشاء ملف الإخراج: %s\n", output_path);
        free(assembled);
        return -1;
    }
    if (index.original_file_size > 0 &&
        fwrite(assembled, 1, (size_t)index.original_file_size, out) != index.original_file_size) {
        fclose(out); free(assembled);
        return -1;
    }
    fclose(out);
    free(assembled);

    fprintf(stdout, "[ads7_unpack] تم بنجاح — كل الأجزاء (%u) والملف الكامل تحققوا سليمين ✅\n",
            index.chunk_count);
    return 0;
}

int ads7_inspect(const char *container_path)
{
    FILE *in = fopen(container_path, "rb");
    if (!in) return -1;

    ads7_index_core_t index;
    if (fread(&index, sizeof(index), 1, in) != 1) { fclose(in); return -1; }
    fclose(in);

    if (index.magic != ADS7_MAGIC) {
        printf("مو ملف ADS-7 صالح.\n");
        return -1;
    }

    printf("=== ADS-7 Container Info ===\n");
    printf("Version           : %u\n", index.version);
    printf("Original size     : %lu bytes\n", (unsigned long)index.original_file_size);
    printf("Chunk count       : %u %s\n", index.chunk_count,
           index.is_single_extent ? "(Single Extent)" : "(Adaptive Striping 7-56)");
    for (uint32_t i = 0; i < index.chunk_count; i++) {
        ads7_chunk_desc_t *d = &index.chunks[i];
        printf("  chunk %-2u | orig=%-8lu comp=%-8lu enc=%-8lu offset=%lu\n",
               d->chunk_id,
               (unsigned long)d->original_size,
               (unsigned long)d->compressed_size,
               (unsigned long)d->encrypted_size,
               (unsigned long)d->offset_in_container);
    }
    return 0;
}
