#include "compress.h"
#include <stdlib.h>
#include <lz4.h>

int ads7_compress(const unsigned char *input, size_t input_len,
                   unsigned char **out_buf, size_t *out_len)
{
    int bound = LZ4_compressBound((int)input_len);
    if (bound <= 0) return -1;

    unsigned char *buf = malloc((size_t)bound);
    if (!buf) return -1;

    int written = LZ4_compress_default((const char *)input, (char *)buf,
                                        (int)input_len, bound);
    if (written <= 0) { free(buf); return -1; }

    *out_buf = buf;
    *out_len = (size_t)written;
    return 0;
}

int ads7_decompress(const unsigned char *input, size_t input_len,
                     size_t original_len, unsigned char **out_buf)
{
    unsigned char *buf = malloc(original_len > 0 ? original_len : 1);
    if (!buf) return -1;

    int written = LZ4_decompress_safe((const char *)input, (char *)buf,
                                       (int)input_len, (int)original_len);
    if (written < 0 || (size_t)written != original_len) { free(buf); return -1; }

    *out_buf = buf;
    return 0;
}
