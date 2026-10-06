#include "parallel.h"
#include "ads7.h"
#include "crypto.h"
#include "compress.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>

/* ---------------------------------------------------------------------
 * أدوات مساعدة
 * --------------------------------------------------------------------- */

static unsigned char *read_whole_file_p(const char *path, uint64_t *out_size)
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

static int pick_thread_count(int requested, uint32_t chunk_count)
{
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1) cores = 4;
    int n = requested > 0 ? requested : (int)cores;
    if ((uint32_t)n > chunk_count) n = (int)chunk_count;
    if (n < 1) n = 1;
    if (n > 32) n = 32; /* سقف أمان */
    return n;
}

/* ---------------------------------------------------------------------
 * PACK المتوازي — المرحلة الثقيلة (ضغط+تشفير+hash) موزّعة على threads
 * --------------------------------------------------------------------- */

typedef struct {
    const unsigned char *ptr;
    uint64_t len;
    ads7_chunk_desc_t *desc;     /* يُملأ مباشرة: hash, iv, tag, original/compressed/encrypted_size */
    unsigned char *out_encrypted;
    int ok;
} pack_job_t;

typedef struct {
    pack_job_t *jobs;
    uint32_t start, end;         /* نطاق [start, end) من الأجزاء يتكفل فيها هالـ thread */
    const unsigned char *key;
} pack_worker_args_t;

static void *pack_worker(void *arg)
{
    pack_worker_args_t *a = (pack_worker_args_t *)arg;

    for (uint32_t i = a->start; i < a->end; i++) {
        pack_job_t *j = &a->jobs[i];

        ads7_sha256(j->ptr, (size_t)j->len, j->desc->hash);

        unsigned char *compressed = NULL; size_t compressed_len = 0;
        if (ads7_compress(j->ptr, (size_t)j->len, &compressed, &compressed_len) != 0) {
            j->ok = 0; continue;
        }

        unsigned char iv[ADS7_AES_IV_LEN];
        if (ads7_random_bytes(iv, ADS7_AES_IV_LEN) != 0) { free(compressed); j->ok = 0; continue; }
        memcpy(j->desc->iv, iv, ADS7_AES_IV_LEN);

        unsigned char *encrypted = NULL; size_t encrypted_len = 0;
        int rc = ads7_encrypt(a->key, iv, compressed, compressed_len,
                               &encrypted, &encrypted_len, j->desc->tag);
        free(compressed);
        if (rc != 0) { j->ok = 0; continue; }

        j->out_encrypted = encrypted;
        j->desc->original_size   = j->len;
        j->desc->compressed_size = compressed_len;
        j->desc->encrypted_size  = encrypted_len;
        j->ok = 1;
    }
    return NULL;
}

int ads7_pack_parallel(const char *input_path, const char *container_path,
                        const char *password, int num_threads)
{
    uint64_t file_size = 0;
    unsigned char *file_data = read_whole_file_p(input_path, &file_size);
    if (!file_data) { fprintf(stderr, "[pack_parallel] فشل قراءة الملف\n"); return -1; }

    ads7_index_core_t index;
    memset(&index, 0, sizeof(index));
    index.magic = ADS7_MAGIC;
    index.version = ADS7_VERSION;
    index.original_file_size = file_size;
    ads7_sha256(file_data, (size_t)file_size, index.full_file_hash);

    uint32_t chunk_count = ads7_calc_chunk_count(file_size);
    index.chunk_count = chunk_count;
    index.is_single_extent = (chunk_count == 1) ? 1 : 0;

    if (ads7_random_bytes(index.salt, ADS7_SALT_LEN) != 0) { free(file_data); return -1; }
    unsigned char key[ADS7_AES_KEY_LEN];
    if (ads7_derive_key(password, index.salt, key) != 0) { free(file_data); return -1; }

    /* تجهيز الأعمال (jobs) — تقسيم نفس حدود الأجزاء المستخدمة بالنسخة التسلسلية */
    pack_job_t *jobs = calloc(chunk_count, sizeof(pack_job_t));
    uint64_t base = file_size / chunk_count, rem = file_size % chunk_count, cursor = 0;
    for (uint32_t i = 0; i < chunk_count; i++) {
        uint64_t len = base + (i < rem ? 1 : 0);
        if (chunk_count == 1) len = file_size;
        jobs[i].ptr = file_data + cursor;
        jobs[i].len = len;
        jobs[i].desc = &index.chunks[i];
        jobs[i].desc->chunk_id = i;
        cursor += len;
    }

    /* --- توزيع الأجزاء على threads وتشغيلهم بالتوازي --- */
    int nthreads = pick_thread_count(num_threads, chunk_count);
    pthread_t *tids = malloc(nthreads * sizeof(pthread_t));
    pack_worker_args_t *wargs = malloc(nthreads * sizeof(pack_worker_args_t));

    uint32_t chunks_per_thread = chunk_count / nthreads;
    uint32_t remT = chunk_count % nthreads;
    uint32_t cur = 0;
    for (int t = 0; t < nthreads; t++) {
        uint32_t n = chunks_per_thread + (t < (int)remT ? 1 : 0);
        wargs[t] = (pack_worker_args_t){ .jobs = jobs, .start = cur, .end = cur + n, .key = key };
        pthread_create(&tids[t], NULL, pack_worker, &wargs[t]);
        cur += n;
    }
    for (int t = 0; t < nthreads; t++) pthread_join(tids[t], NULL);
    free(tids); free(wargs);

    for (uint32_t i = 0; i < chunk_count; i++) {
        if (!jobs[i].ok) {
            fprintf(stderr, "[pack_parallel] فشل معالجة الجزء %u\n", i);
            for (uint32_t k = 0; k < chunk_count; k++) free(jobs[k].out_encrypted);
            free(jobs); free(file_data);
            return -1;
        }
    }

    /* --- الكتابة الفعلية (تسلسلية، سريعة لأنها بس I/O مو معالجة) --- */
    FILE *out = fopen(container_path, "wb+");
    if (!out) { for (uint32_t k=0;k<chunk_count;k++) free(jobs[k].out_encrypted); free(jobs); free(file_data); return -1; }

    fseek(out, sizeof(ads7_index_core_t), SEEK_SET);
    uint64_t offset = sizeof(ads7_index_core_t);
    for (uint32_t i = 0; i < chunk_count; i++) {
        index.chunks[i].offset_in_container = offset;
        fwrite(jobs[i].out_encrypted, 1, index.chunks[i].encrypted_size, out);
        offset += index.chunks[i].encrypted_size;
    }

    /* --- Parity (نفس منطق V2) --- */
    uint64_t max_len = 0;
    for (uint32_t i = 0; i < chunk_count; i++)
        if (index.chunks[i].encrypted_size > max_len) max_len = index.chunks[i].encrypted_size;

    unsigned char *parity = calloc(1, max_len);
    for (uint32_t i = 0; i < chunk_count; i++) {
        for (uint64_t b = 0; b < index.chunks[i].encrypted_size; b++)
            parity[b] ^= jobs[i].out_encrypted[b];
        free(jobs[i].out_encrypted);
    }
    free(jobs);

    index.has_parity = 1;
    index.parity_offset = offset;
    index.parity_len = max_len;
    fwrite(parity, 1, max_len, out);
    free(parity);

    fseek(out, 0, SEEK_SET);
    fwrite(&index, sizeof(index), 1, out);
    fclose(out);
    free(file_data);

    fprintf(stdout, "[pack_parallel] تم بـ %d threads: %u جزء\n", nthreads, chunk_count);
    return 0;
}

/* ---------------------------------------------------------------------
 * UNPACK المتوازي — القراءة عبر pread() (آمن تماماً لعدة threads بنفس الوقت)
 * --------------------------------------------------------------------- */

typedef struct {
    const ads7_chunk_desc_t *desc;
    unsigned char *out_ptr;      /* مكان الكتابة جوا assembled buffer — منطقة منفصلة لكل thread */
    int ok;
} unpack_job_t;

typedef struct {
    unpack_job_t *jobs;
    uint32_t start, end;
    int fd;
    const unsigned char *key;
} unpack_worker_args_t;

static void *unpack_worker(void *arg)
{
    unpack_worker_args_t *a = (unpack_worker_args_t *)arg;

    for (uint32_t i = a->start; i < a->end; i++) {
        unpack_job_t *j = &a->jobs[i];
        const ads7_chunk_desc_t *d = j->desc;

        unsigned char *ciphertext = malloc(d->encrypted_size);
        ssize_t r = pread(a->fd, ciphertext, d->encrypted_size, (off_t)d->offset_in_container);
        if (r < 0 || (uint64_t)r != d->encrypted_size) { free(ciphertext); j->ok = 0; continue; }

        unsigned char *compressed = NULL; size_t compressed_len = 0;
        if (ads7_decrypt(a->key, d->iv, ciphertext, d->encrypted_size, d->tag,
                          &compressed, &compressed_len) != 0) {
            free(ciphertext); j->ok = 0; continue;
        }
        free(ciphertext);

        unsigned char *original = NULL;
        if (ads7_decompress(compressed, compressed_len, (size_t)d->original_size, &original) != 0) {
            free(compressed); j->ok = 0; continue;
        }
        free(compressed);

        unsigned char check[ADS7_SHA256_LEN];
        ads7_sha256(original, (size_t)d->original_size, check);
        if (memcmp(check, d->hash, ADS7_SHA256_LEN) != 0) {
            fprintf(stderr, "[unpack_parallel] ⚠️ تلف بالجزء %u — النسخة المتوازية ما تسوي شفاء ذاتي، استخدم 'unpack' العادي\n", i);
            free(original); j->ok = 0; continue;
        }

        memcpy(j->out_ptr, original, d->original_size);
        free(original);
        j->ok = 1;
    }
    return NULL;
}

int ads7_unpack_parallel(const char *container_path, const char *output_path,
                          const char *password, int num_threads)
{
    FILE *hf = fopen(container_path, "rb");
    if (!hf) return -1;
    ads7_index_core_t index;
    if (fread(&index, sizeof(index), 1, hf) != 1) { fclose(hf); return -1; }
    fclose(hf);

    if (index.magic != ADS7_MAGIC) { fprintf(stderr, "[unpack_parallel] magic غير صالح\n"); return -1; }

    unsigned char key[ADS7_AES_KEY_LEN];
    if (ads7_derive_key(password, index.salt, key) != 0) return -1;

    int fd = open(container_path, O_RDONLY);
    if (fd < 0) return -1;

    unsigned char *assembled = malloc(index.original_file_size > 0 ? index.original_file_size : 1);
    unpack_job_t *jobs = calloc(index.chunk_count, sizeof(unpack_job_t));

    uint64_t cursor = 0;
    for (uint32_t i = 0; i < index.chunk_count; i++) {
        jobs[i].desc = &index.chunks[i];
        jobs[i].out_ptr = assembled + cursor;
        cursor += index.chunks[i].original_size;
    }

    int nthreads = pick_thread_count(num_threads, index.chunk_count);
    pthread_t *tids = malloc(nthreads * sizeof(pthread_t));
    unpack_worker_args_t *wargs = malloc(nthreads * sizeof(unpack_worker_args_t));

    uint32_t per = index.chunk_count / nthreads, remT = index.chunk_count % nthreads, cur = 0;
    for (int t = 0; t < nthreads; t++) {
        uint32_t n = per + (t < (int)remT ? 1 : 0);
        wargs[t] = (unpack_worker_args_t){ .jobs = jobs, .start = cur, .end = cur + n, .fd = fd, .key = key };
        pthread_create(&tids[t], NULL, unpack_worker, &wargs[t]);
        cur += n;
    }
    for (int t = 0; t < nthreads; t++) pthread_join(tids[t], NULL);
    free(tids); free(wargs);
    close(fd);

    for (uint32_t i = 0; i < index.chunk_count; i++) {
        if (!jobs[i].ok) {
            fprintf(stderr, "[unpack_parallel] فشل بالجزء %u\n", i);
            free(jobs); free(assembled);
            return -2;
        }
    }
    free(jobs);

    unsigned char full_check[ADS7_SHA256_LEN];
    ads7_sha256(assembled, (size_t)index.original_file_size, full_check);
    if (memcmp(full_check, index.full_file_hash, ADS7_SHA256_LEN) != 0) {
        fprintf(stderr, "[unpack_parallel] ⚠️ hash الملف الكامل غير مطابق!\n");
        free(assembled);
        return -2;
    }

    FILE *out = fopen(output_path, "wb");
    if (!out) { free(assembled); return -1; }
    if (index.original_file_size > 0)
        fwrite(assembled, 1, (size_t)index.original_file_size, out);
    fclose(out);
    free(assembled);

    fprintf(stdout, "[unpack_parallel] تم بنجاح — %u جزء، تحقق كامل سليم ✅\n", index.chunk_count);
    return 0;
}
