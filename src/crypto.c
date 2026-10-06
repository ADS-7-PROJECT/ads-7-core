#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define PBKDF2_ITERATIONS 200000

int ads7_random_bytes(unsigned char *buf, size_t len)
{
    return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}

int ads7_derive_key(const char *password, const unsigned char *salt,
                     unsigned char out_key[ADS7_AES_KEY_LEN])
{
    int rc = PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                                salt, ADS7_SALT_LEN,
                                PBKDF2_ITERATIONS,
                                EVP_sha256(),
                                ADS7_AES_KEY_LEN, out_key);
    return rc == 1 ? 0 : -1;
}

void ads7_sha256(const unsigned char *data, size_t len,
                  unsigned char out_hash[ADS7_SHA256_LEN])
{
    SHA256(data, len, out_hash);
}

int ads7_encrypt(const unsigned char *key, const unsigned char *iv,
                  const unsigned char *plaintext, size_t plaintext_len,
                  unsigned char **out_buf, size_t *out_len,
                  unsigned char out_tag[ADS7_GCM_TAG_LEN])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    /* GCM ما يضيف padding — الناتج بنفس طول النص الأصلي بالضبط */
    unsigned char *buf = malloc(plaintext_len > 0 ? plaintext_len : 1);
    if (!buf) { EVP_CIPHER_CTX_free(ctx); return -1; }

    int len1 = 0, len2 = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ADS7_GCM_IV_LEN, NULL) != 1) goto fail;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto fail;

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, buf, &len1, plaintext, (int)plaintext_len) != 1) goto fail;
    }
    if (EVP_EncryptFinal_ex(ctx, buf + len1, &len2) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ADS7_GCM_TAG_LEN, out_tag) != 1) goto fail;

    EVP_CIPHER_CTX_free(ctx);
    *out_buf = buf;
    *out_len = (size_t)(len1 + len2);
    return 0;

fail:
    EVP_CIPHER_CTX_free(ctx);
    free(buf);
    return -1;
}

int ads7_decrypt(const unsigned char *key, const unsigned char *iv,
                  const unsigned char *ciphertext, size_t ciphertext_len,
                  const unsigned char tag[ADS7_GCM_TAG_LEN],
                  unsigned char **out_buf, size_t *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    unsigned char *buf = malloc(ciphertext_len > 0 ? ciphertext_len : 1);
    if (!buf) { EVP_CIPHER_CTX_free(ctx); return -1; }

    int len1 = 0, len2 = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ADS7_GCM_IV_LEN, NULL) != 1) goto fail;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto fail;

    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(ctx, buf, &len1, ciphertext, (int)ciphertext_len) != 1) goto fail;
    }

    /* نمرر بصمة التوثيق قبل الـ Final — لو غير مطابقة، Final يفشل ويرفض البيانات بالكامل */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ADS7_GCM_TAG_LEN, (void *)tag) != 1) goto fail;
    if (EVP_DecryptFinal_ex(ctx, buf + len1, &len2) != 1) goto fail; /* ⚠️ هنا يفشل لو فيه تلاعب/تلف */

    EVP_CIPHER_CTX_free(ctx);
    *out_buf = buf;
    *out_len = (size_t)(len1 + len2);
    return 0;

fail:
    EVP_CIPHER_CTX_free(ctx);
    free(buf);
    return -1;
}
