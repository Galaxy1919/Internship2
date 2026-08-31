/*
 * test_autokey.c — Autokey Cipher（明文自密钥）测试
 *
 * 覆盖：手算向量 / 含非字母往返 / 短明文 / 单字母密钥 /
 *       空串 / 非法密钥校验 / 长度保持
 *
 * compile: cd .. && gcc -Wall -Wextra -std=gnu99 -DAUTOKEY_NO_MAIN -o test/test_autokey test/test_autokey.c main.c
 * usage:   ./test/test_autokey
 */

#include <stdio.h>
#include <string.h>

/* 主文件暴露的接口 */
extern int autokey_encrypt(const char *key, const char *plain, char *cipher);
extern int autokey_decrypt(const char *key, const char *cipher, char *plain);

static int fail_count = 0;

static void expect(int cond, const char *what)
{
    if (cond) {
        printf("[PASS] %s\n", what);
    } else {
        printf("[FAIL] %s\n", what);
        fail_count++;
    }
}

int main(void)
{
    char out[4096];

    /* 1. 手算向量：ATTACKATDAWN + KEY = KXRAVDAVNAPQ
     * 密钥流 = KEY + 明文前 9 个字母 = K E Y A T T A C K A T D
     * 最后一位 N + D = 13+3 = 16 = Q */
    autokey_encrypt("KEY", "ATTACKATDAWN", out);
    expect(strcmp(out, "KXRAVDAVNAPQ") == 0, "手算向量加密");
    autokey_decrypt("KEY", "KXRAVDAVNAPQ", out);
    expect(strcmp(out, "ATTACKATDAWN") == 0, "手算向量解密");

    /* 2. 含非字母字符：空格保留原位，不消耗密钥流
     * ATTACK|sp|AT|sp|DAWN → 字母加密 KXRAVD AV NAPQ */
    autokey_encrypt("KEY", "ATTACK AT DAWN", out);
    expect(strcmp(out, "KXRAVD AV NAPQ") == 0, "非字母原样保留");
    autokey_decrypt("KEY", "KXRAVD AV NAPQ", out);
    expect(strcmp(out, "ATTACK AT DAWN") == 0, "含空格往返");

    /* 3. 短明文：明文短于密钥时仅用密钥前缀 */
    autokey_encrypt("SECRET", "AB", out);
    expect(strcmp(out, "SF") == 0, "明文短于密钥");
    autokey_decrypt("SECRET", "SF", out);
    expect(strcmp(out, "AB") == 0, "短明文往返");

    /* 4. 单字母密钥 ≠ Caesar：密钥流 = 密钥 + 明文本身
     * ABC + B：A+B=B, B+A=B, C+B=D → BBD
     * （Autokey 密钥流不循环，这是与 Vigenere 的本质区别） */
    autokey_encrypt("B", "ABC", out);
    expect(strcmp(out, "BBD") == 0, "单字母密钥=BBD（非Caesar）");

    /* 5. 空串 */
    autokey_encrypt("KEY", "", out);
    expect(strcmp(out, "") == 0, "空串");

    /* 6. 密钥校验：空/含数字/含小写（非大写字母）均应拒绝 */
    expect(autokey_encrypt("", "ABC", out) != 0, "空密钥拒绝");
    expect(autokey_encrypt("K3Y", "ABC", out) != 0, "含数字密钥拒绝");
    expect(autokey_encrypt("key", "ABC", out) != 0, "小写密钥拒绝");

    /* 7. 长度保持：密文与明文等长（含非字母） */
    autokey_encrypt("KEY", "HELLO, WORLD!", out);
    expect(strlen(out) == strlen("HELLO, WORLD!"), "密文长度保持");

    printf(fail_count ? "\n存在失败用例\n" : "\n全部测试通过\n");
    return fail_count ? 1 : 0;
}
