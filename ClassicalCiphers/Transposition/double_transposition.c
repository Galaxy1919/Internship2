/*
 * double_transposition.c — 双重置换密码（Double-Transposition Cipher）
 *
 * 原理：明文按行填入 n 列矩阵，按密钥指定的列序逐列读出完成一轮置换；
 *       对结果再用第二个密钥做一轮置换，共两轮。
 * 密钥：数字排列串，如 "3124" 表示列序 [3,1,2,4]（1-based）。
 *       两个密钥列数必须相同（保证两轮矩阵行数一致）。
 * 填充：明文长度不是列数倍数时，矩阵末尾补 'X'，解密后截断即可。
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -o dt double_transposition.c
 * usage:   ./dt           交互式加解密演示
 *          ./dt selftest  内置测试向量自检
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define MAX_TEXT 4096   /* 明文/密文最大长度 */
#define MAX_COLS 16     /* 最大列数 */

/* 置换密钥：n 列，perm 为列序（1-based），inv 为逆映射（解密用） */
typedef struct {
    int n;
    int perm[MAX_COLS];
    int inv[MAX_COLS];
} TransKey;

/* 解析数字排列密钥："3124" -> perm={3,1,2,4}, n=4 */
/* 非法输入（非数字/数字重复/越界）返回 0 */
static int key_parse(TransKey *k, const char *s)
{
    int len = (int)strlen(s);
    if (len < 2 || len > MAX_COLS)
        return 0;
    for (int i = 0; i < len; i++)
        if (!isdigit((unsigned char)s[i]))
            return 0;

    int used[MAX_COLS] = {0};
    for (int i = 0; i < len; i++) {
        int v = s[i] - '0';
        if (v < 1 || v > len || used[v])
            return 0;               /* 必须由 1..n 各出现一次 */
        used[v] = 1;
        k->perm[i] = v;
    }
    k->n = len;

    for (int v = 1; v <= len; v++)  /* inv[v] = 列 v 在 perm 中的下标 */
        for (int i = 0; i < len; i++)
            if (k->perm[i] == v) {
                k->inv[v] = i;
                break;
            }
    return 1;
}

/* 单轮列置换加密：按列序逐列读出，长度不足补 'X'，返回 padded 长度 */
static int column_enc(const TransKey *k, const char *in, int len, char *out)
{
    int n = k->n;
    int rows = (len + n - 1) / n;   /* 矩阵行数（向上取整） */
    int o = 0;
    for (int ci = 0; ci < n; ci++) {
        int col = k->perm[ci] - 1;
        for (int r = 0; r < rows; r++) {
            int idx = r * n + col;
            out[o++] = (idx < len) ? in[idx] : 'X'; /* 缺位补 X */
        }
    }
    return o;                       /* 输出长度恒为 rows*n */
}

/* 单轮列置换解密：密文按段填回各列（第 i 段属于列 perm[i]），再按行读出 */
static int column_dec(const TransKey *k, const char *in, int len, char *out)
{
    int n = k->n;
    int rows = len / n;             /* 密文长度必为 n 的倍数 */
    for (int ci = 0; ci < n; ci++) {
        int col = k->perm[ci] - 1;
        for (int r = 0; r < rows; r++)
            out[r * n + col] = in[ci * rows + r];
    }
    return rows * n;
}

/* 双重置换加密：两轮 column_enc，密文长度（含填充）写入 *out_len */
/* 缓冲区不足返回 -1 */
int dt_encrypt(const TransKey *k1, const TransKey *k2,
               const char *plain, int plain_len,
               char *cipher, int *out_len)
{
    char mid[MAX_TEXT];
    int mid_len;
    if (plain_len + k1->n > MAX_TEXT)   /* padded 后可能超出缓冲 */
        return -1;
    mid_len = column_enc(k1, plain, plain_len, mid);
    *out_len = column_enc(k2, mid, mid_len, cipher);
    return 0;
}

/* 双重置换解密：两轮 column_dec（先 k2 后 k1），返回 padded 明文长度 */
int dt_decrypt(const TransKey *k1, const TransKey *k2,
               const char *cipher, int cipher_len, char *plain)
{
    char mid[MAX_TEXT];
    int mid_len = column_dec(k2, cipher, cipher_len, mid);
    return column_dec(k1, mid, mid_len, plain);
}

/* 单个自测用例：加密结果必须等于期望密文，解密必须还原明文 */
static int check_case(const char *name, const char *k1s, const char *k2s,
                      const char *plain, const char *expect, int expect_len)
{
    TransKey k1, k2;
    char cipher[MAX_TEXT], dec[MAX_TEXT];
    int clen, plen = (int)strlen(plain);

    if (!key_parse(&k1, k1s) || !key_parse(&k2, k2s)) {
        printf("[FAIL] %s: 密钥解析失败\n", name);
        return 0;
    }
    if (dt_encrypt(&k1, &k2, plain, plen, cipher, &clen) != 0) {
        printf("[FAIL] %s: 加密缓冲不足\n", name);
        return 0;
    }
    if (clen != expect_len || memcmp(cipher, expect, (size_t)expect_len) != 0) {
        printf("[FAIL] %s: 密文不符 期望[%.*s] 实际[%.*s]\n",
               name, expect_len, expect, clen, cipher);
        return 0;
    }

    dt_decrypt(&k1, &k2, cipher, clen, dec);
    if (plen != 0 && memcmp(dec, plain, (size_t)plen) != 0) {
        printf("[FAIL] %s: 解密不符 期望[%s] 实际[%.*s]\n",
               name, plain, plen, dec);
        return 0;
    }
    printf("[PASS] %s\n", name);
    return 1;
}

/* 内置自检：手算测试向量 + 往返验证 + 密钥校验 */
static int selftest(void)
{
    int pass = 1;
    TransKey k;

    /* 密文期望值均为手算结果：
     * 例1 无填充：ABCDEFGH 8字符 n=4 rows=2
     * 例2 有填充：HELLO 5字符 n=4 rows=2 补3个X
     */
    pass &= check_case("无填充往返", "2143", "4321",
                       "ABCDEFGH", "EGACFHBD", 8);
    pass &= check_case("有填充往返", "3124", "2413",
                       "HELLO", "XXOXLEHL", 8);
    pass &= check_case("单字符填充", "12", "21", "A", "XA", 2);
    pass &= check_case("空串", "12", "21", "", "", 0);

    /* 密钥校验：非数字 / 重复 / 越界 / 单列 均应拒绝 */
    if (key_parse(&k, "12a4")) { printf("[FAIL] 密钥含非数字未拦截\n"); pass = 0; }
    if (key_parse(&k, "1123")) { printf("[FAIL] 密钥重复数字未拦截\n"); pass = 0; }
    if (key_parse(&k, "1235")) { printf("[FAIL] 密钥越界未拦截\n"); pass = 0; }
    if (key_parse(&k, "1"))    { printf("[FAIL] 单列密钥未拦截\n"); pass = 0; }
    if (!key_parse(&k, "3124")) { printf("[FAIL] 合法密钥被拒\n"); pass = 0; }

    printf(pass ? "\n全部测试通过\n" : "\n存在失败用例\n");
    return pass ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "selftest") == 0)
        return selftest();

    char plain[MAX_TEXT], k1s[MAX_COLS + 1], k2s[MAX_COLS + 1];
    TransKey k1, k2;
    char cipher[MAX_TEXT], dec[MAX_TEXT];
    int clen;

    printf("===== 双重置换密码 (Double-Transposition) =====\n");
    printf("明文(<=%d字符): ", MAX_TEXT - 64);
    if (!fgets(plain, sizeof(plain) - 64, stdin)) return 1;
    plain[strcspn(plain, "\n")] = '\0';
    printf("密钥1(数字排列, 如3124): ");
    if (!fgets(k1s, sizeof(k1s), stdin)) return 1;
    k1s[strcspn(k1s, "\n")] = '\0';
    printf("密钥2(与密钥1列数相同): ");
    if (!fgets(k2s, sizeof(k2s), stdin)) return 1;
    k2s[strcspn(k2s, "\n")] = '\0';

    if (!key_parse(&k1, k1s) || !key_parse(&k2, k2s)) {
        printf("密钥非法：需为 1..n 各出现一次的数字排列\n");
        return 1;
    }
    if (k1.n != k2.n) {
        printf("两个密钥列数必须相同（如都是4位）\n");
        return 1;
    }

    int plen = (int)strlen(plain);
    if (dt_encrypt(&k1, &k2, plain, plen, cipher, &clen) != 0) {
        printf("明文过长\n");
        return 1;
    }
    cipher[clen] = '\0';
    printf("\n密文(%d字符): %s\n", clen, cipher);

    dt_decrypt(&k1, &k2, cipher, clen, dec);
    dec[plen] = '\0';               /* 截掉填充字符 */
    printf("解密(%d字符): %s\n", plen, dec);

    printf("%s\n", strcmp(plain, dec) == 0 ? "[OK] 往返验证通过" : "[FAIL] 往返不一致");
    return 0;
}
