/*
 * shamir.h — Shamir's Secret Sharing على حقل GF(256)
 *
 * هذا التطبيق الحقيقي لفكرة "37 ملف حماية، يحتاج النظام أجزاء منهم بس"
 * اللي اتفقنا عليها لنظام الأختام. بالضبط نفس الخوارزمية المستخدمة بأدوات
 * حقيقية مثل ssss.
 *
 * خاصية أمنية مهمة (رياضياً مثبتة، مو مجرد ادعاء): أي عدد أجزاء **أقل من
 * العتبة (K)** — حتى لو K-1 بالضبط — لا يكشف **ولا بت واحد** من السر
 * الأصلي. هذا معناته أجزاء الحماية ما تحتاج تشفير إضافي فوقها؛ الحماية
 * الرياضية بالخوارزمية نفسها كافية.
 */

#ifndef ADS7_SHAMIR_H
#define ADS7_SHAMIR_H

#include <stdint.h>
#include <stddef.h>

#define SHAMIR_SECRET_LEN 32   /* حجم المفتاح الرئيسي (AES-256) */
#define SHAMIR_MAX_SHARES 255  /* حد GF(256) نفسه */

/* جزء واحد (Share) = رقم تعريفي (x) + بيانات (y) بنفس طول السر */
typedef struct {
    uint8_t id;                          /* رقم الجزء: 1..255 (0 محجوز للسر نفسه) */
    unsigned char data[SHAMIR_SECRET_LEN];
} shamir_share_t;

/* يقسّم secret (32 بايت) إلى n جزء، يحتاج أي k منهم لإعادة البناء.
 * out_shares: مصفوفة مجهزة مسبقاً بحجم n */
int shamir_split(const unsigned char secret[SHAMIR_SECRET_LEN],
                  int n, int k, shamir_share_t *out_shares);

/* يعيد بناء السر من k جزء (أو أكثر) — لازم تكون كل الـ id مختلفة عن بعض */
int shamir_combine(const shamir_share_t *shares, int k,
                    unsigned char out_secret[SHAMIR_SECRET_LEN]);

#endif
