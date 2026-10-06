CC      = gcc
# ملاحظة بيئة: liblz4-dev/libssl-dev مو متوفرين هالجلسة (الشبكة محجوبة بالكامل،
# حتى apt). نستخدم هيدرز OpenSSL المرفقة مع Node.js (موجودة أصلاً بالنظام)
# + هيدر lz4.h مصغّر مكتوب يدوياً بـ vendor/include، ونربط مباشرة بملفات
# .so.3/.so.1 المثبتة فعلياً (بدون الحاجة لـ symlinks الـ -dev). هذا تحسين
# مؤقت فقط — يُستبدل بـ apt install عادي أول ما تتوفر الشبكة.
CFLAGS  = -Wall -Wextra -O2 -Iinclude -Ivendor/include -I/usr/include/node
LDFLAGS = /usr/lib/x86_64-linux-gnu/liblz4.so.1 \
          /usr/lib/x86_64-linux-gnu/libssl.so.3 \
          /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
          -lpthread

SRC = src/chunker.c src/crypto.c src/compress.c src/pack.c src/unpack.c src/repo.c src/keymgmt.c src/seal.c src/parallel.c src/main.c
OBJ = $(SRC:.c=.o)
BIN = build/ads7

all: $(BIN)

$(BIN): $(OBJ)
	@mkdir -p build
	$(CC) $(OBJ) -o $(BIN) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all clean
