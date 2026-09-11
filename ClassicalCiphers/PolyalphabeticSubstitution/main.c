/*
 * main.c — Autokey Cipher（明文自密钥）— 多表替代密码
 *
 * 原理：Vigenere 1586 年原始设计。密钥流前 keylen 位来自密钥，
 *       之后逐位来自明文本身（明文字母序列），因此密钥流不循环。
 * 加密：C[i] = (P[i] + K[i]) mod 26
 * 解密：P[i] = (C[i] - K[i]) mod 26，密钥流用已解出的明文补齐
 *       （解密必须逐位串行推进，这是 Autokey 与 Vigenere 的本质区别）
 * 约定：仅处理大写 A-Z，非字母字符原样保留且不消耗密钥流。
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -o autokey main.c
 * usage:   ./autokey           交互式加解密演示
 *          测试见 test/test_autokey.c
 */

#include <ctype.h>       /* 备用（isalpha 等），当前主要用自写的 letter_index */
#include <stdio.h>       /* printf/fgets/fprintf */
#include <string.h>      /* strlen/strcmp/strcspn */

#define MAX_TEXT 4096    /* 明文/密文最大长度 */
#define MAX_KEY 128      /* 密钥最大长度 */

/* 字母转 0-25 索引；非大写字母返回 -1 */
static int letter_index(char c)
{
    return (c >= 'A' && c <= 'Z') ? c - 'A' : -1;  /* 大写字母转 0..25,否则 -1 */
}

/* 密钥校验：必须为 1..MAX_KEY 个大写字母 */
static int key_valid(const char *key)
{
    size_t len = strlen(key);           /* 密钥长度 */
    if (len < 1 || len > MAX_KEY)       /* 长度必须在 1..MAX_KEY */
        return 0;
    for (size_t i = 0; i < len; i++)    /* 逐字符检查 */
        if (letter_index(key[i]) < 0)   /* 非大写字母即非法 */
            return 0;
    return 1;                           /* 全部合法 */
}

/* 核心变换：decrypt=0 加密，decrypt=1 解密
 * letters[] 记录明文侧字母序列（加密记录输入，解密记录解出结果），
 * 密钥流第 j 位在 j>=keylen 时取 letters[j-keylen] */
static int autokey_transform(const char *key, const char *in, char *out,
                             int decrypt)
{
    int keylen = (int)strlen(key);      /* 初始密钥长度 */
    char letters[MAX_TEXT];     /* 已处理的明文字母序列 */
    int j = 0;                  /* 已处理字母数 */

    for (int i = 0; in[i]; i++) {       /* 逐字符遍历输入,直到遇 '\0' */
        int p = letter_index(in[i]);    /* 当前字符转字母索引 */
        if (p < 0) {                    /* 非字母：原样保留 */
            out[i] = in[i];             /* 非字母原样保留，不消耗密钥流 */
            continue;                   /* 跳过,不推进 j */
        }
        int k = (j < keylen) ? letter_index(key[j])      /* 前 keylen 位用密钥 */
                             : letter_index(letters[j - keylen]);  /* 之后用明文侧字母 */
        int r = decrypt ? (p - k + 26) % 26 : (p + k) % 26;  /* 解密减(加26防负)/加密加,模26 */
        out[i] = (char)('A' + r);       /* 索引转回大写字母写入输出 */
        letters[j] = decrypt ? out[i] : in[i];  /* 记录明文侧字母（字符） */
        j++;                            /* 已处理字母数 +1 */
    }
    out[strlen(in)] = '\0';             /* 输出补字符串结束符 */
    return 0;
}

/* 加密：返回 0 成功，密钥非法返回 -1 */
int autokey_encrypt(const char *key, const char *plain, char *cipher)
{
    if (!key_valid(key))                /* 密钥非法直接拒绝 */
        return -1;
    return autokey_transform(key, plain, cipher, 0);  /* decrypt=0 加密 */
}

/* 解密：返回 0 成功，密钥非法返回 -1 */
int autokey_decrypt(const char *key, const char *cipher, char *plain)
{
    if (!key_valid(key))                /* 密钥非法直接拒绝 */
        return -1;
    return autokey_transform(key, cipher, plain, 1);  /* decrypt=1 解密 */
}

/* 交互演示入口：测试编译时用 -DAUTOKEY_NO_MAIN 排除（见 test/test_autokey.c） */
#ifndef AUTOKEY_NO_MAIN
int main(int argc, char **argv)
{
    /* 命令行数据模式（供 Python 桥接层 subprocess 调用，stdout 单行结果）：
     *   ./autokey enc <KEY> <TEXT>   加密：输出密文
     *   ./autokey dec <KEY> <TEXT>   解密：输出明文
     * 与交互模式共用同一套核心函数，无填充、长度不变。 */
    if (argc >= 4 && (strcmp(argv[1], "enc") == 0 || strcmp(argv[1], "dec") == 0)) {
        char out[MAX_TEXT];             /* 输出缓冲 */
        int r = (argv[1][0] == 'e') ? autokey_encrypt(argv[2], argv[3], out)  /* enc 分支 */
                                    : autokey_decrypt(argv[2], argv[3], out);  /* dec 分支 */
        if (r != 0) {                   /* 密钥非法 */
            fprintf(stderr, "密钥非法：需为 1..%d 个大写字母\n", MAX_KEY);
            return 1;
        }
        printf("%s\n", out);            /* 单行输出结果 */
        return 0;
    }

    char key[MAX_KEY + 1], plain[MAX_TEXT], cipher[MAX_TEXT], dec[MAX_TEXT];  /* 交互缓冲 */

    printf("===== Autokey Cipher (明文自密钥) =====\n");
    printf("密钥(大写字母, 如KEY): ");
    if (!fgets(key, sizeof(key), stdin)) return 1;  /* 读密钥 */
    key[strcspn(key, "\n")] = '\0';     /* 去换行 */
    if (!key_valid(key)) {              /* 校验密钥 */
        printf("密钥非法：需为 1..%d 个大写字母\n", MAX_KEY);
        return 1;
    }
    printf("明文(大写字母, 其他字符原样保留): ");
    if (!fgets(plain, sizeof(plain), stdin)) return 1;  /* 读明文 */
    plain[strcspn(plain, "\n")] = '\0'; /* 去换行 */

    autokey_encrypt(key, plain, cipher);  /* 加密 */
    printf("\n密文: %s\n", cipher);

    autokey_decrypt(key, cipher, dec);    /* 解密 */
    printf("解密: %s\n", dec);

    printf("%s\n", strcmp(plain, dec) == 0 ? "[OK] 往返验证通过" : "[FAIL] 往返不一致");  /* 比较往返结果 */
    return 0;
}
#endif /* AUTOKEY_NO_MAIN */
