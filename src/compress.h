/*
 * compress.h — طبقة الضغط (LZ4) — الخطوة الأولى بدورة الكتابة قبل التشفير
 */

#ifndef ADS7_COMPRESS_H
#define ADS7_COMPRESS_H

#include <stddef.h>

/* يضغط buffer بـ LZ4. يخصص out_buf ديناميكياً (على المستدعي تحريره) */
int ads7_compress(const unsigned char *input, size_t input_len,
                   unsigned char **out_buf, size_t *out_len);

/* يفك ضغط buffer — original_len لازم يكون معروف مسبقاً (مخزن بالـ Index Core) */
int ads7_decompress(const unsigned char *input, size_t input_len,
                     size_t original_len, unsigned char **out_buf);

#endif
