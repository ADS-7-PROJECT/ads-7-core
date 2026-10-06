/*
 * repo.h — Deduplication (منع تكرار البيانات)
 *
 * فكرة الميزة: بدل ما كل ملف يُحزم بحاوية .ads7 منفصلة تماماً، نسوي "مستودع"
 * (repo) مشترك — أي جزء (chunk) بصمته (hash) اتشافت من قبل بأي ملف ثاني
 * جوا نفس المستودع، ما يُخزن مرة ثانية، بس يُشار له. هذا يوفر مساحة كبيرة
 * لما فيه ملفات متشابهة أو نفس الملف بنسخ متعددة.
 *
 * بنية المستودع على القرص:
 *   <repo>/chunks/<sha256_hex>.chunk   = [IV 16 بايت][بيانات مشفرة (LZ4+AES256)]
 *   <repo>/manifests/<name>.ads7m      = "قائمة" الملف — بيانات وصفية بس،
 *                                         تشير لأجزاء بالـ hash، بدون تكرار البيانات
 *
 * ⚠️ تبسيط متعمد لهذي النسخة: بدون Parity/Erasure Coding بعد (ميزة V2 بالحاوية
 * العادية) — الدمج بين الاثنين (dedup + parity) نقطة مفتوحة موثقة بـ PROJECT.md.
 */

#ifndef ADS7_REPO_H
#define ADS7_REPO_H

/* يحزم ملف داخل مستودع مشترك (repo_dir) — أي جزء مكرر (نفس الـ hash) من
 * ملف سابق بنفس المستودع ما يُخزن مرة ثانية.
 * manifest_name: اسم منطقي للملف داخل المستودع (بدون امتداد) */
int ads7_repo_pack(const char *repo_dir, const char *input_path,
                    const char *manifest_name, const char *password);

/* يفك ملف من المستودع عبر اسم الـ manifest حقه */
int ads7_repo_unpack(const char *repo_dir, const char *manifest_name,
                      const char *output_path, const char *password);

/* يطبع إحصائيات المستودع: كم جزء فريد مخزن، الحجم الفعلي على القرص،
 * وكم "توفّر" فعلياً بسبب الدمج (مقارنة بالحجم لو ما كان فيه dedup) */
int ads7_repo_stats(const char *repo_dir);

/* يحذف manifest ملف من المستودع — **لا يلمس الأجزاء (chunks) نفسها إطلاقاً**،
 * لأن أجزاء ثانية (ملفات ثانية) ممكن تكون لسا تستخدمها. هذا بالضبط سبب
 * الحاجة لـ ads7_repo_gc منفصلة بعدها. */
int ads7_repo_delete(const char *repo_dir, const char *manifest_name);

/* V5: Garbage Collection — يفحص كل الـ manifests الموجودة فعلياً، يجمع كل
 * بصمات الأجزاء المُشار لها، وأي جزء بمجلد chunks/ ماله أي manifest يشير
 * له (= "يتيم" — بقي من ملف انحذف manifest حقه)، يُحذف فعلياً. يرجع عدد
 * الأجزاء المحذوفة والبايتات المُحرَّرة. */
int ads7_repo_gc(const char *repo_dir);

#endif
