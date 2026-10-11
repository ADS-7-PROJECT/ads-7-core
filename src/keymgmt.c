#include "keymgmt.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ADS7_KEYS_MAGIC 0x4B455953u /* "KEYS" */

/* --- بنية ملف repo.keys: هيدر + خانتين ثابتتين --- */
typedef struct {
    unsigned char salt[ADS7_SALT_LEN];
    unsigned char iv[ADS7_AES_IV_LEN];
    unsigned char tag[ADS7_GCM_TAG_LEN];   /* بصمة توثيق GCM لهذي الخانة تحديداً */
    unsigned char wrapped_key[ADS7_MASTER_KEY_LEN]; /* GCM بدون padding = نفس طول المفتاح بالضبط */
} keyslot_t;

typedef struct {
    uint32_t magic;
    keyslot_t slot_password;
    keyslot_t slot_recovery;
} keys_file_t;

/* قائمة كلمات مصغّرة للتوضيح (نسخة ديمو — ليست قائمة Diceware الكاملة 7776 كلمة،
 * تلك نقطة تحسين مستقبلية موثقة). كافية لإثبات الفكرة وإعطاء entropy معقول. */
static const char *WORDLIST[] = {
    "raven","quartz","velvet","copper","ember","tundra","basalt","willow",
    "cobalt","meadow","garnet","cinder","hollow","marble","sable","thistle",
    "onyx","cedar","frost","amber","brisk","drift","ferrous","glint",
    "harbor","ivory","jasper","kindle","lunar","mirth","nectar","opal",
    "pewter","quill","ridge","slate","talon","umber","violet","wisp"
};
#define WORDLIST_SIZE (sizeof(WORDLIST) / sizeof(WORDLIST[0]))

static int is_used(uint32_t idx, const uint32_t *used, int used_count)
{
    for (int k = 0; k < used_count; k++) if (used[k] == idx) return 1;
    return 0;
}

static void generate_recovery_phrase(char out[ADS7_RECOVERY_MAX_LEN])
{
    unsigned char rnd[16];
    ads7_random_bytes(rnd, sizeof(rnd));

    const char *symbols = "!@#$%^&*-+=?";
    char buf[ADS7_RECOVERY_MAX_LEN];
    int pos = 0;

    uint32_t used[4]; int used_count = 0;
    for (int w = 0; w < 4; w++) {
        uint32_t idx;
        int retries = 0;
        do {
            unsigned char extra;
            ads7_random_bytes(&extra, 1);
            idx = extra % WORDLIST_SIZE;
            retries++;
        } while (is_used(idx, used, used_count) && retries < 10);
        used[used_count++] = idx;

        pos += snprintf(buf + pos, sizeof(buf) - pos, "%s%s",
                         WORDLIST[idx], (w < 3) ? "-" : "");
    }
    /* نضيف رمزين ورقمين عشوائيين بالنهاية لزيادة entropy وتعقيد التخمين */
    pos += snprintf(buf + pos, sizeof(buf) - pos, "-%c%c%02u",
                     symbols[rnd[8] % 12], symbols[rnd[9] % 12], rnd[10] % 100);

    memcpy(out, buf, (size_t)pos + 1);
}

static int wrap_key(const char *credential, const unsigned char master[ADS7_MASTER_KEY_LEN],
                     keyslot_t *slot)
{
    if (ads7_random_bytes(slot->salt, ADS7_SALT_LEN) != 0) return -1;
    if (ads7_random_bytes(slot->iv, ADS7_AES_IV_LEN) != 0) return -1;

    unsigned char kek[ADS7_AES_KEY_LEN];
    if (ads7_derive_key(credential, slot->salt, kek) != 0) return -1;

    unsigned char *wrapped = NULL; size_t wrapped_len = 0;
    if (ads7_encrypt(kek, slot->iv, master, ADS7_MASTER_KEY_LEN,
                      &wrapped, &wrapped_len, slot->tag) != 0)
        return -1;

    if (wrapped_len != ADS7_MASTER_KEY_LEN) { free(wrapped); return -1; }
    memcpy(slot->wrapped_key, wrapped, wrapped_len);
    free(wrapped);
    return 0;
}

static int unwrap_key(const char *credential, const keyslot_t *slot,
                       unsigned char out_master[ADS7_MASTER_KEY_LEN])
{
    unsigned char kek[ADS7_AES_KEY_LEN];
    if (ads7_derive_key(credential, slot->salt, kek) != 0) return -1;

    unsigned char *plain = NULL; size_t plain_len = 0;
    if (ads7_decrypt(kek, slot->iv, slot->wrapped_key, ADS7_MASTER_KEY_LEN,
                      slot->tag, &plain, &plain_len) != 0) {
        return -1; /* credential غلط أو تلف — GCM يرفض فوراً لو الـ tag ما طابق */
    }
    if (plain_len != ADS7_MASTER_KEY_LEN) { free(plain); return -1; }
    memcpy(out_master, plain, ADS7_MASTER_KEY_LEN);
    free(plain);
    return 0;
}

int ads7_generate_passphrase(char *out, size_t out_size)
{
    char buf[ADS7_RECOVERY_MAX_LEN];
    generate_recovery_phrase(buf);
    size_t needed = strlen(buf) + 1;
    if (needed > out_size) return -1;
    memcpy(out, buf, needed);
    return 0;
}

int ads7_keymgmt_exists(const char *repo_dir)
{
    char path[1200];
    snprintf(path, sizeof(path), "%s/repo.keys", repo_dir);
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

int ads7_keymgmt_init(const char *repo_dir, const char *password,
                       unsigned char out_master_key[ADS7_MASTER_KEY_LEN],
                       char out_recovery_phrase[ADS7_RECOVERY_MAX_LEN])
{
    if (ads7_random_bytes(out_master_key, ADS7_MASTER_KEY_LEN) != 0) return -1;
    generate_recovery_phrase(out_recovery_phrase);

    keys_file_t kf;
    memset(&kf, 0, sizeof(kf));
    kf.magic = ADS7_KEYS_MAGIC;

    if (wrap_key(password, out_master_key, &kf.slot_password) != 0) return -1;
    if (wrap_key(out_recovery_phrase, out_master_key, &kf.slot_recovery) != 0) return -1;

    char path[1200];
    snprintf(path, sizeof(path), "%s/repo.keys", repo_dir);
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(&kf, sizeof(kf), 1, f);
    fclose(f);
    return 0;
}

int ads7_keymgmt_unlock(const char *repo_dir, const char *credential,
                         unsigned char out_master_key[ADS7_MASTER_KEY_LEN])
{
    char path[1200];
    snprintf(path, sizeof(path), "%s/repo.keys", repo_dir);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    keys_file_t kf;
    if (fread(&kf, sizeof(kf), 1, f) != 1) { fclose(f); return -1; }
    fclose(f);

    if (kf.magic != ADS7_KEYS_MAGIC) return -1;

    if (unwrap_key(credential, &kf.slot_password, out_master_key) == 0) return 0;
    if (unwrap_key(credential, &kf.slot_recovery, out_master_key) == 0) return 0;

    return -1; /* فشلت الخانتين */
}
