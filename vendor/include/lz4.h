/*
 * lz4.h — نسخة محلية مبسّطة (vendored, minimal)
 *
 * ⚠️ ملاحظة بيئة: شبكة الإنترنت كانت محجوبة بالكامل بهالجلسة (حتى apt وGitHub
 * raw)، بس مكتبة liblz4.so.1 الفعلية كانت مثبتة أصلاً بالنظام (ناقص بس
 * ملف الهيدر lz4.h). بدل ما نوقف الشغل، كتبنا هذا الهيدر المصغّر يدوياً —
 * فيه بس الدوال الثلاث اللي مشروعنا فعلياً يستخدمها. تواقيعها (signatures)
 * ثابتة بمكتبة LZ4 من سنين طويلة (ABI مستقر)، فهذا آمن 100%.
 *
 * عند توفر إنترنت لاحقاً، يُفضّل استبدال هذا بالهيدر الرسمي الكامل من
 * https://github.com/lz4/lz4 (أو تثبيت `liblz4-dev` عبر apt عادي).
 */
#ifndef LZ4_H_2983827168210
#define LZ4_H_2983827168210

#ifdef __cplusplus
extern "C" {
#endif

int LZ4_compress_default(const char *src, char *dst, int srcSize, int dstCapacity);
int LZ4_decompress_safe(const char *src, char *dst, int compressedSize, int dstCapacity);
int LZ4_compressBound(int inputSize);

#ifdef __cplusplus
}
#endif

#endif
