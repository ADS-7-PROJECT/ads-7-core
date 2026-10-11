/*
 * parallel.h — محرك قراءة/كتابة متوازي (V5)
 *
 * المشكلة بالأدوات التقليدية (`cat` وأغلب أدوات لينكس): تستخدم fread/fwrite
 * (stdio) اللي تحافظ على "موضع ملف" تسلسلي مشترك — بطبيعتها غير قابلة
 * للتوازي بسهولة.
 *
 * بما إن ADS-7 يقسم الملف أصلاً لـ 7-56 جزء مستقل تماماً (تشفير/ضغط/hash
 * منفصلين لكل جزء)، هذا التصميم مثالي للتوازي من جذوره:
 *   - الكتابة (Pack): كل جزء يُضغط ويُشفّر ويُحسب hash حقه بـ thread منفصل
 *     (هذا الجزء الثقيل على المعالج — أكبر فايدة من التوازي هنا).
 *   - القراءة (Unpack): نستخدم pread() — نداء POSIX ياخذ إزاحة (offset)
 *     صريحة بكل نداء، آمن تماماً لعدة threads بنفس الوقت على نفس الملف
 *     بدون أي قفل أو تضارب على "موضع" مشترك (عكس fread العادي).
 *
 * ⚠️ تبسيط موثق: نسخة القراءة المتوازية هذي **ما فيها إعادة بناء عبر
 * Parity** (V2 self-healing) — لو جزء تلف، ترجع فشل صريح بدل محاولة
 * الإصلاح. الدمج بين التوازي والشفاء الذاتي نقطة مفتوحة مستقبلية.
 */

#ifndef ADS7_PARALLEL_H
#define ADS7_PARALLEL_H

/* num_threads: 0 = اختيار تلقائي (عدد الأجزاء أو عدد الأنوية، أيهم أصغر) */
int ads7_pack_parallel(const char *input_path, const char *container_path,
                        const char *password, int num_threads);

int ads7_unpack_parallel(const char *container_path, const char *output_path,
                          const char *password, int num_threads);

#endif
