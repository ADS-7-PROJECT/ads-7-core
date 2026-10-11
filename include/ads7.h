/*
 * ADS-7 (Advanced Disk System-7) — "Smart 7"
 * Phase 1: Userspace prototype library
 *
 * هذا الملف يعرّف البنية الأساسية لملف ADS-7 المطابقة للتصميم المتفق عليه:
 *   - الحمولة (Payload): مضغوطة (LZ4) + مشفرة (AES-256-CBC) + مقسمة (7-56 جزء)
 *   - العقل المدبر (Index Core): ميتاداتا تحتوي خريطة الأجزاء وبصماتها (SHA-256)
 *   - عتبة الـ 1MB: أي ملف أصغر يُحفظ كجزء واحد (Single Extent)
 *
 * ملاحظة: هذا نموذج أولي (Phase 1) لاختبار المنطق الأساسي بأمان بالـ userspace
 * قبل أي انتقال لكتابة kernel module. لا يحتوي بعد على:
 *   - Erasure Coding / Parity Blocks (سيُضاف Phase 1.1)
 *   - سلسلة Smart Index الموزعة (يُختبر حالياً بنسخة Index واحدة مركزية)
 *   - Write-Ahead Log (WAL)
 */

#ifndef ADS7_H
#define ADS7_H

#include <stdint.h>
#include <stddef.h>

/* ---------------------------------------------------------------------
 * الثوابت الأساسية للتصميم
 * --------------------------------------------------------------------- */

#define ADS7_MAGIC              0x41445337u   /* "ADS7" */
#define ADS7_VERSION            1

/* عتبة الملف الصغير: أقل من 1MB = جزء واحد بدون تقسيم */
#define ADS7_SMALL_FILE_THRESHOLD   (1024u * 1024u)

/* حدود التجزئة التكيفية (Adaptive Striping) */
#define ADS7_MIN_CHUNKS          7
#define ADS7_MAX_CHUNKS          56

#define ADS7_SHA256_LEN          32
#define ADS7_AES_KEY_LEN         32   /* AES-256 */
#define ADS7_GCM_IV_LEN          12   /* AES-256-GCM: nonce قياسي 12 بايت (مو 16 متل CBC) */
#define ADS7_GCM_TAG_LEN         16   /* بصمة التوثيق (Authentication Tag) — تكتشف أي تلاعب تلقائياً */
#define ADS7_AES_IV_LEN          ADS7_GCM_IV_LEN
#define ADS7_SALT_LEN            16

/* ---------------------------------------------------------------------
 * وصف جزء واحد (Chunk) — يُخزن ضمن الـ Index Core
 * --------------------------------------------------------------------- */
typedef struct {
    uint32_t chunk_id;                      /* ترقيم الجزء داخل الملف: 0..n-1 */
    uint64_t offset_in_container;           /* موقع الجزء داخل ملف الحاوية (.ads7) */
    uint64_t compressed_size;               /* الحجم بعد الضغط (قبل التشفير) */
    uint64_t encrypted_size;                /* الحجم الفعلي المكتوب بالحاوية (بعد AES padding) */
    uint64_t original_size;                 /* الحجم الأصلي لهذا الجزء قبل الضغط */
    unsigned char iv[ADS7_AES_IV_LEN];      /* IV/Nonce خاص بهذا الجزء (فريد لكل جزء) */
    unsigned char tag[ADS7_GCM_TAG_LEN];    /* بصمة توثيق GCM — تكتشف أي تعديل بالبيانات فوراً عند الفك */
    unsigned char hash[ADS7_SHA256_LEN];    /* SHA-256 لبيانات الجزء بعد فك التشفير/الضغط
                                                (تُستخدم للتحقق من السلامة عند القراءة) */
} ads7_chunk_desc_t;

/* ---------------------------------------------------------------------
 * العقل المدبر (Index Core) — الميتاداتا الكاملة للملف
 * --------------------------------------------------------------------- */
typedef struct {
    uint32_t magic;                         /* ADS7_MAGIC للتحقق من صحة الملف */
    uint32_t version;
    uint64_t original_file_size;
    uint32_t chunk_count;                   /* 1 لو ملف صغير، أو 7-56 لو كبير */
    uint8_t  is_single_extent;              /* 1 = ملف صغير غير مقسم */

    unsigned char salt[ADS7_SALT_LEN];      /* لاشتقاق مفتاح AES من كلمة مرور المستخدم (PBKDF2) */

    /* بصمة SHA-256 للملف الأصلي بالكامل (قبل التقسيم) — للتحقق النهائي بعد إعادة التجميع */
    unsigned char full_file_hash[ADS7_SHA256_LEN];

    /* --- V2: Parity Block (XOR-based single-fault-tolerant Erasure Coding) ---
     * درع الحماية (Parity Blocks) — نسخة أولى مبسطة:
     * parity = XOR لكل الأجزاء المشفرة (بعد padding للصفر لأطول جزء)
     * يسمح باستعادة **جزء واحد تالف كحد أقصى** (مو أكثر) — هذا تبسيط متعمد
     * لأول نسخة؛ الترقية لـ Reed-Solomon الكامل (تحمل عدة أجزاء تالفة بنفس الوقت)
     * مؤجلة لمرحلة لاحقة، موثقة بـ PROJECT.md ضمن "نقاط مفتوحة".
     */
    uint8_t  has_parity;
    uint64_t parity_offset;
    uint64_t parity_len;      /* = أطول encrypted_size بين كل الأجزاء */

    ads7_chunk_desc_t chunks[ADS7_MAX_CHUNKS];
} ads7_index_core_t;

/* ---------------------------------------------------------------------
 * واجهات المكتبة
 * --------------------------------------------------------------------- */

/* يحسب عدد الأجزاء المناسب لحجم ملف معين وفق قاعدة "سمارت 7":
 *   - أصغر من 1MB → يرجع 1 (Single Extent)
 *   - غير ذلك → قيمة تكيفية بين 7 و 56 حسب الحجم */
uint32_t ads7_calc_chunk_count(uint64_t file_size);

/* يحزم ملف من القرص إلى حاوية ADS-7 (.ads7) — يطبق الدورة كاملة:
 * فحص الحجم → ضغط LZ4 → تشفير AES-256 → تقسيم → توليد hash لكل جزء → كتابة Index Core
 *
 * password: تُستخدم لاشتقاق مفتاح AES-256 عبر PBKDF2 (نموذج أولي بسيط لإدارة المفاتيح)
 * إرجاع: 0 عند النجاح، قيمة سالبة عند الفشل */
int ads7_pack(const char *input_path, const char *container_path, const char *password);

/* يفك حاوية ADS-7 ويعيد بناء الملف الأصلي، مع التحقق من hash كل جزء و hash الملف الكامل
 * إرجاع: 0 عند النجاح (والتحقق سليم)، قيمة سالبة عند أي فشل أو تلف مكتشف */
int ads7_unpack(const char *container_path, const char *output_path, const char *password);

/* يطبع معلومات الـ Index Core لملف حاوية (بدون فك التشفير) — أداة تشخيص/فحص */
int ads7_inspect(const char *container_path);

#endif /* ADS7_H */
