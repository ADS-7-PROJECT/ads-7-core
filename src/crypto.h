/*
 * crypto.h — طبقة التشفير والفحص (Payload encryption + integrity hashing)
 *
 * تغطي بند "الحمولة (Payload)": تشفير AES-256، وبند "الشفاء الذاتي":
 * حساب SHA-256 لكل جزء يُستخدم للتحقق من سلامته عند القراءة.
 *
 * ملاحظة أمنية صريحة (Phase 1 — نموذج أولي فقط):
 *   - اشتقاق المفتاح هنا عبر PBKDF2 من كلمة مرور يعطيها المستخدم بسطر الأوامر.
 *   - هذا **غير كافٍ** لنموذج تهديد حقيقي (كلمة المرور تظهر بتاريخ الأوامر،
 *     ومافي إدارة مفاتيح فعلية). نقطة "Key Management" المذكورة بـ PROJECT.md
 *     لسا مفتوحة ولازم تُحل قبل أي استخدام إنتاجي.
 */

#ifndef ADS7_CRYPTO_H
#define ADS7_CRYPTO_H

#include <stddef.h>
#include "ads7.h"

/* يشتق مفتاح AES-256 من كلمة مرور + salt عبر PBKDF2-HMAC-SHA256 */
int ads7_derive_key(const char *password, const unsigned char *salt,
                     unsigned char out_key[ADS7_AES_KEY_LEN]);

/* يشفر buffer بـ AES-256-GCM. يخصص out_buf ديناميكياً (على المستدعي تحريره).
 * out_tag: بصمة التوثيق (16 بايت) — لازم تُخزن وتُمرر لـ ads7_decrypt لاحقاً */
int ads7_encrypt(const unsigned char *key, const unsigned char *iv,
                  const unsigned char *plaintext, size_t plaintext_len,
                  unsigned char **out_buf, size_t *out_len,
                  unsigned char out_tag[ADS7_GCM_TAG_LEN]);

/* يفك تشفير buffer بـ AES-256-GCM مع التحقق من بصمة التوثيق.
 * ⚠️ لو tag غير مطابق (البيانات اتعدلت أو تلفت)، الدالة ترجع -1 فوراً
 * ولا تُرجع أي بيانات — هذا أقوى من CBC اللي كان ممكن "يفك" بيانات تالفة
 * بصمت لو التلف ما أثر على الـ padding */
int ads7_decrypt(const unsigned char *key, const unsigned char *iv,
                  const unsigned char *ciphertext, size_t ciphertext_len,
                  const unsigned char tag[ADS7_GCM_TAG_LEN],
                  unsigned char **out_buf, size_t *out_len);

/* يحسب SHA-256 لبيانات معينة */
void ads7_sha256(const unsigned char *data, size_t len,
                  unsigned char out_hash[ADS7_SHA256_LEN]);

/* يولّد بايتات عشوائية آمنة (لـ salt و IV) */
int ads7_random_bytes(unsigned char *buf, size_t len);

#endif
