/*
 * main.c — RSA-1024 公钥密码交互演示
 *
 * 流程：生成 1024 位密钥 → 输入明文 → 公钥加密 → CRT 解密还原
 * 实现见 rsa.h/rsa.c（大整数层 rsa_bn.h/rsa_bn.c），测试见 test/。
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -o rsa main.c rsa.c rsa_bn.c
 * usage:   ./rsa           交互演示（自动生成密钥并加解密）
 */

#include <stdio.h>
#include <string.h>

#include "rsa.h"

static void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
}

static void print_rbn(const char *tag, const rbn_t a)
{
    char hex[257];
    rbn_to_hex(a, hex);
    printf("%s: %s\n", tag, hex);
}

int main(void)
{
    RSA_KEY key;
    uint8_t plain[RSA_MAX_BLOCK];
    uint8_t cipher[128];
    uint8_t dec[128];
    size_t dlen;

    printf("===== RSA-1024 =====\n");
    printf("正在生成 1024 位密钥（大素数生成中，约 1-10 秒）...\n");
    if (rsa_keygen(&key, 1024) != 0) {
        printf("密钥生成失败\n");
        return 1;
    }
    print_rbn("n   ", key.n);
    print_rbn("e   ", key.e);
    print_rbn("d   ", key.d);
    print_rbn("p   ", key.p);
    print_rbn("q   ", key.q);

    printf("\n明文(<=%d字节): ", RSA_MAX_BLOCK - 1);
    if (!fgets((char *)plain, sizeof(plain), stdin))
        return 1;
    size_t plen = strlen((char *)plain);
    while (plen > 0 && (plain[plen - 1] == '\n' || plain[plen - 1] == '\r'))
        plain[--plen] = '\0';

    if (rsa_encrypt(&key, plain, plen, cipher) != 0) {
        printf("明文过长或 ≥ n，请缩短\n");
        return 1;
    }
    printf("密文(128字节): ");
    print_hex(cipher, 128);
    printf("\n");

    if (rsa_decrypt(&key, cipher, dec, &dlen) != 0) {
        printf("解密失败\n");
        return 1;
    }
    char out[RSA_MAX_BLOCK + 1];
    memcpy(out, dec + 128 - dlen, dlen);    /* 明文在 128 字节输出的尾部 */
    out[dlen] = '\0';
    printf("解密: %s\n", out);

    printf("%s\n",
           (dlen == plen && memcmp(plain, dec + 128 - dlen, plen) == 0)
               ? "[OK] 往返验证通过"
               : "[FAIL] 往返不一致");
    return 0;
}
