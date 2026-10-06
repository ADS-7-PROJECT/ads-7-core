/*
 * chunker.c — منطق "سمارت 7" (Adaptive Striping)
 *
 * القاعدة المتفق عليها:
 *   - ملف < 1MB  → جزء واحد (Single Extent) لتجنب I/O Amplification
 *   - ملف >= 1MB → 7 إلى 56 جزء، يزيد العدد تدريجياً مع حجم الملف
 *
 * ملاحظة صريحة: صيغة النمو الحالية (كل 16MB يضيف جزء واحد) هي قيمة
 * ابتدائية قابلة للتعديل — تحتاج ضبط لاحقاً بعد قياسات أداء حقيقية
 * (نقطة "الأداء الفعلي مقابل ZFS/ext4" المذكورة بـ PROJECT.md).
 */

#include "ads7.h"

#define ADS7_GROWTH_STEP_MB  16u

uint32_t ads7_calc_chunk_count(uint64_t file_size)
{
    if (file_size < ADS7_SMALL_FILE_THRESHOLD) {
        return 1; /* Single Extent */
    }

    uint64_t size_mb = file_size / (1024u * 1024u);
    uint64_t extra_chunks = size_mb / ADS7_GROWTH_STEP_MB;

    uint64_t total = (uint64_t)ADS7_MIN_CHUNKS + extra_chunks;

    if (total < ADS7_MIN_CHUNKS) total = ADS7_MIN_CHUNKS;
    if (total > ADS7_MAX_CHUNKS) total = ADS7_MAX_CHUNKS;

    return (uint32_t)total;
}
