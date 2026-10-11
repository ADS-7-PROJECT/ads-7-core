/*
 * keymgmt.h — إدارة مفاتيح بأسلوب LUKS/BitLocker (Key Encryption Key wrapping)
 *
 * بدل "الباسورد يشتق مفتاح التشفير مباشرة" (الأسلوب القديم بـ V1/V2)،
 * نسوي فصل حقيقي:
 *   - "المفتاح الرئيسي" (Master Key / DEK - Data Encryption Key): 32 بايت
 *     عشوائية 100% (CSPRNG)، هذا اللي يشفر البيانات فعلياً. أقوى بكثير من
 *     أي مفتاح مشتق من باسورد بشري (حتى لو الباسورد قوي، عنده entropy أقل
 *     من مفتاح عشوائي خام).
 *   - المفتاح الرئيسي **مو مخزن بصيغته الخام أبداً** — يُخزن "ملفوف" (wrapped
 *     = مشفر) داخل "خانات مفاتيح" (keyslots) متعددة. كل خانة تُفتح بوسيلة
 *     مختلفة (باسورد المستخدم، أو عبارة استرجاع تلقائية).
 *   - عبارة الاسترجاع التلقائية: كلمات + أرقام + رموز، تُعرض للمستخدم **مرة
 *     وحدة فقط** وقت الإنشاء — نفس فلسفة "recovery key" بـ BitLocker/FileVault.
 *
 * ⚠️ تبسيط موثق: التغليف (wrapping) هنا يستخدم AES-256-CBC (نفس طبقة
 * التشفير الموجودة بالمشروع أصلاً). المعيار الصناعي الأدق يستخدم AES-GCM
 * (تشفير موثّق authenticated) لخانات المفاتيح تحديداً — نقطة تحسين مستقبلية
 * موثقة بـ PROJECT.md.
 */

#ifndef ADS7_KEYMGMT_H
#define ADS7_KEYMGMT_H

#include <stddef.h>
#include "ads7.h"

#define ADS7_MASTER_KEY_LEN   ADS7_AES_KEY_LEN   /* 32 بايت */
#define ADS7_RECOVERY_MAX_LEN 128

/* ينشئ مفتاح رئيسي عشوائي جديد + يولّد عبارة استرجاع، ويكتب ملف
 * <repo_dir>/repo.keys فيه خانتين: (0) باسورد المستخدم، (1) عبارة الاسترجاع.
 * out_master_key: يرجع المفتاح الرئيسي بالذاكرة للاستخدام الفوري.
 * out_recovery_phrase: يرجع عبارة الاسترجاع كنص — لازم تُعرض للمستخدم فوراً
 *   ويُطلب منه يحفظها بمكان آمن، لأنها **ما تُخزن ولا تُعرض مرة ثانية أبداً**. */
int ads7_keymgmt_init(const char *repo_dir, const char *password,
                       unsigned char out_master_key[ADS7_MASTER_KEY_LEN],
                       char out_recovery_phrase[ADS7_RECOVERY_MAX_LEN]);

/* يفتح المفتاح الرئيسي من ملف repo.keys الموجود، عبر تجربة الـ credential
 * كباسورد (خانة 0) أولاً، وإذا فشل يجربه كعبارة استرجاع (خانة 1).
 * يرجع 0 لو نجح فتح أي خانة، -1 لو فشلت الاثنتين. */
int ads7_keymgmt_unlock(const char *repo_dir, const char *credential,
                         unsigned char out_master_key[ADS7_MASTER_KEY_LEN]);

/* true لو ملف repo.keys موجود أصلاً (يعني المستودع مهيّأ من قبل) */
int ads7_keymgmt_exists(const char *repo_dir);

/* أداة مستقلة: تولّد عبارة قوية (كلمات + أرقام + رموز) بدون ربطها بأي
 * مستودع — مفيدة كأداة CLI مستقلة (`ads7 keygen`) لو المستخدم يبي يولّد
 * باسورد قوي لاستخدامه بأي مكان، مو بس كعبارة استرجاع. */
int ads7_generate_passphrase(char *out, size_t out_size);

#endif
