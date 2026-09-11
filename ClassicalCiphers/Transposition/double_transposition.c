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

#include <ctype.h>       /* isdigit 判断数字 */
#include <stdio.h>       /* printf/fgets 等 IO */
#include <string.h>      /* strlen/memcmp/strcspn 等 */

#define MAX_TEXT 4096   /* 明文/密文最大长度 */
#define MAX_COLS 16     /* 最大列数 */

/* 置换密钥：n 列，perm 为列序（1-based），inv 为逆映射（解密用） */
typedef struct {
    int n;                  /* 列数（也是密钥长度） */
    int perm[MAX_COLS];     /* perm[i] = 第 i 轮读取的列号(1-based) */
    int inv[MAX_COLS];      /* inv[v] = 列号 v 在 perm 中的下标 */
} TransKey;

/* 解析数字排列密钥："3124" -> perm={3,1,2,4}, n=4 */
/* 非法输入（非数字/数字重复/越界）返回 0 */
static int key_parse(TransKey *k, const char *s)
{
    int len = (int)strlen(s);           /* 密钥串长度 */
    if (len < 2 || len > MAX_COLS)      /* 长度必须 2..MAX_COLS */
        return 0;
    for (int i = 0; i < len; i++)       /* 逐字符检查是否都是数字 */
        if (!isdigit((unsigned char)s[i]))
            return 0;

    int used[MAX_COLS] = {0};           /* 出现标记数组：used[v]=1 表示数字 v 已用过 */
    for (int i = 0; i < len; i++) {
        int v = s[i] - '0';             /* 字符转数字 */
        if (v < 1 || v > len || used[v])  /* 必须由 1..n 各出现一次：越界或重复都拒绝 */
            return 0;
        used[v] = 1;                    /* 标记该数字已用 */
        k->perm[i] = v;                 /* 记录第 i 轮的列号 */
    }
    k->n = len;                         /* 保存列数 */

    for (int v = 1; v <= len; v++)      /* inv[v] = 列 v 在 perm 中的下标 */
        for (int i = 0; i < len; i++)   /* 在 perm 里找列号等于 v 的位置 */
            if (k->perm[i] == v) {
                k->inv[v] = i;          /* 记录逆映射：列 v 出现在 perm 第 i 位 */
                break;                  /* 找到即可跳出内层循环 */
            }
    return 1;                           /* 解析成功 */
}

/* 单轮列置换加密：按列序逐列读出，长度不足补 'X'，返回 padded 长度 */
static int column_enc(const TransKey *k, const char *in, int len, char *out)
{
    int n = k->n;                       /* 列数 */
    int rows = (len + n - 1) / n;       /* 矩阵行数（向上取整） */
    int o = 0;                          /* 输出游标 */
    for (int ci = 0; ci < n; ci++) {    /* 按 perm 顺序逐列读取 */
        int col = k->perm[ci] - 1;      /* 当前读取的列(0-based) */
        for (int r = 0; r < rows; r++) {  /* 该列从上到下逐行取 */
            int idx = r * n + col;      /* 矩阵第 r 行第 col 列的下标 */
            out[o++] = (idx < len) ? in[idx] : 'X'; /* 有字符取字符,越界补 X */
        }
    }
    return o;                           /* 输出长度恒为 rows*n */
}

/* 单轮列置换解密：密文按段填回各列（第 i 段属于列 perm[i]），再按行读出 */
static int column_dec(const TransKey *k, const char *in, int len, char *out)
{
    int n = k->n;                       /* 列数 */
    int rows = len / n;                 /* 密文长度必为 n 的倍数 */
    for (int ci = 0; ci < n; ci++) {    /* 密文第 ci 段对应列 perm[ci] */
        int col = k->perm[ci] - 1;      /* 该段对应的原列号(0-based) */
        for (int r = 0; r < rows; r++)  /* 把这一段逐字符填回该列第 r 行 */
            out[r * n + col] = in[ci * rows + r];
    }
    return rows * n;                    /* 返回恢复出的矩阵总长度 */
}

/* 双重置换加密：两轮 column_enc，密文长度（含填充）写入 *out_len */
/* 缓冲区不足返回 -1 */
int dt_encrypt(const TransKey *k1, const TransKey *k2,
               const char *plain, int plain_len,
               char *cipher, int *out_len)
{
    char mid[MAX_TEXT];                 /* 中间密文缓冲 */
    int mid_len;
    if (plain_len + k1->n > MAX_TEXT)   /* padded 后可能超出缓冲 */
        return -1;
    mid_len = column_enc(k1, plain, plain_len, mid);  /* 第一轮：K1 加密 */
    *out_len = column_enc(k2, mid, mid_len, cipher);  /* 第二轮：K2 加密 */
    return 0;
}

/* 双重置换解密：两轮 column_dec（先 k2 后 k1），返回 padded 明文长度 */
int dt_decrypt(const TransKey *k1, const TransKey *k2,
               const char *cipher, int cipher_len, char *plain)
{
    char mid[MAX_TEXT];                 /* 中间缓冲 */
    int mid_len = column_dec(k2, cipher, cipher_len, mid);  /* 先撤销最后一轮 K2 */
    return column_dec(k1, mid, mid_len, plain);             /* 再撤销第一轮 K1 */
}

/* 单个自测用例：加密结果必须等于期望密文，解密必须还原明文 */
static int check_case(const char *name, const char *k1s, const char *k2s,
                      const char *plain, const char *expect, int expect_len)
{
    TransKey k1, k2;                    /* 两个密钥 */
    char cipher[MAX_TEXT], dec[MAX_TEXT];  /* 密文与解密缓冲 */
    int clen, plen = (int)strlen(plain);  /* plen = 原始明文长度 */

    if (!key_parse(&k1, k1s) || !key_parse(&k2, k2s)) {  /* 解析两个密钥,失败则算错 */
        printf("[FAIL] %s: 密钥解析失败\n", name);
        return 0;
    }
    if (dt_encrypt(&k1, &k2, plain, plen, cipher, &clen) != 0) {  /* 加密,检查缓冲是否够 */
        printf("[FAIL] %s: 加密缓冲不足\n", name);
        return 0;
    }
    if (clen != expect_len || memcmp(cipher, expect, (size_t)expect_len) != 0) {  /* 比对期望密文 */
        printf("[FAIL] %s: 密文不符 期望[%.*s] 实际[%.*s]\n",
               name, expect_len, expect, clen, cipher);
        return 0;
    }

    dt_decrypt(&k1, &k2, cipher, clen, dec);  /* 解密回环 */
    if (plen != 0 && memcmp(dec, plain, (size_t)plen) != 0) {  /* 比对解密结果与原文 */
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
    int pass = 1;                       /* 总体通过标志 */
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
    if (argc > 1 && strcmp(argv[1], "selftest") == 0)  /* 自检模式 */
        return selftest();

    /* 命令行数据模式（供 Python 桥接层 subprocess 调用）：
     *   ./dt enc <K1> <K2> <TEXT>             加密 → stdout: "<4位hex明文长>:<密文>"
     *   ./dt dec <K1> <K2> <长度前缀:密文>     解密 → stdout: 明文
     * 本实现用 'X' 补齐矩阵，密文本身不含原始明文长度；解密端必须知道
     * 明文长度才能截掉填充，故 enc 输出统一携带 4 位十六进制明文长度前缀。 */
    if (argc >= 5 && (strcmp(argv[1], "enc") == 0 || strcmp(argv[1], "dec") == 0)) {
        TransKey k1, k2;
        if (!key_parse(&k1, argv[2]) || !key_parse(&k2, argv[3])) {  /* 解析两个密钥 */
            fprintf(stderr, "密钥非法：需为 1..n 各出现一次的数字排列\n");
            return 1;
        }
        if (k1.n != k2.n) {                 /* 两个密钥列数必须一致 */
            fprintf(stderr, "两个密钥列数必须相同\n");
            return 1;
        }
        if (argv[1][0] == 'e') {            /* enc 分支 */
            int plen = (int)strlen(argv[4]);  /* 明文长度 */
            char cipher[MAX_TEXT];
            int clen;
            if (plen + k1.n > MAX_TEXT) {   /* 明文过长检查 */
                fprintf(stderr, "明文过长\n");
                return 1;
            }
            if (dt_encrypt(&k1, &k2, argv[4], plen, cipher, &clen) != 0) {  /* 双重加密 */
                fprintf(stderr, "加密失败\n");
                return 1;
            }
            cipher[clen] = '\0';            /* 密文补字符串结束符 */
            printf("%04x:%s\n", plen, cipher);  /* 输出"4位hex明文长:密文" */
            return 0;
        }
        /* dec <K1> <K2> <4位hex明文长>:<密文> */
        {
            const char *s = argv[4];        /* 待解析的"长度:密文"串 */
            size_t slen = strlen(s);
            int plen = 0;                   /* 解析出的明文长度 */
            if (slen < 6 || s[4] != ':') {  /* 至少要 "0000:x" 共 6 字符,且第 5 字符是冒号 */
                fprintf(stderr, "密文格式应为 <4位hex明文长>:<密文>\n");
                return 1;
            }
            for (int i = 0; i < 4; i++) {   /* 逐字符解析 4 位十六进制长度前缀 */
                char c = s[i];
                int v = (c >= '0' && c <= '9') ? c - '0'          /* 数字 0-9 */
                      : (c >= 'a' && c <= 'f') ? c - 'a' + 10     /* 小写 a-f */
                      : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;  /* 大写 A-F,否则非法 */
                if (v < 0) {                /* 非十六进制字符 */
                    fprintf(stderr, "长度前缀非法\n");
                    return 1;
                }
                plen = plen * 16 + v;       /* 累加成十进制长度 */
            }
            const char *cipher = s + 5;     /* 冒号之后是密文 */
            int clen = (int)strlen(cipher); /* 密文长度 */
            char dec[MAX_TEXT];
            if (clen > MAX_TEXT || plen < 0 || plen > clen) {  /* 长度合理性检查 */
                fprintf(stderr, "密文长度异常\n");
                return 1;
            }
            dt_decrypt(&k1, &k2, cipher, clen, dec);  /* 双重解密 */
            dec[plen] = '\0';               /* 截掉填充字符 */
            printf("%s\n", dec);
            return 0;
        }
    }

    char plain[MAX_TEXT], k1s[MAX_COLS + 1], k2s[MAX_COLS + 1];  /* 交互模式缓冲 */
    TransKey k1, k2;
    char cipher[MAX_TEXT], dec[MAX_TEXT];
    int clen;

    printf("===== 双重置换密码 (Double-Transposition) =====\n");
    printf("明文(<=%d字符): ", MAX_TEXT - 64);
    if (!fgets(plain, sizeof(plain) - 64, stdin)) return 1;  /* 读明文,失败则退出 */
    plain[strcspn(plain, "\n")] = '\0';     /* 去掉末尾换行符 */
    printf("密钥1(数字排列, 如3124): ");
    if (!fgets(k1s, sizeof(k1s), stdin)) return 1;  /* 读密钥1 */
    k1s[strcspn(k1s, "\n")] = '\0';         /* 去换行 */
    printf("密钥2(与密钥1列数相同): ");
    if (!fgets(k2s, sizeof(k2s), stdin)) return 1;  /* 读密钥2 */
    k2s[strcspn(k2s, "\n")] = '\0';         /* 去换行 */

    if (!key_parse(&k1, k1s) || !key_parse(&k2, k2s)) {  /* 解析密钥,非法则退出 */
        printf("密钥非法：需为 1..n 各出现一次的数字排列\n");
        return 1;
    }
    if (k1.n != k2.n) {                     /* 两密钥列数必须一致 */
        printf("两个密钥列数必须相同（如都是4位）\n");
        return 1;
    }

    int plen = (int)strlen(plain);          /* 明文长度 */
    if (dt_encrypt(&k1, &k2, plain, plen, cipher, &clen) != 0) {  /* 双重加密 */
        printf("明文过长\n");
        return 1;
    }
    cipher[clen] = '\0';                    /* 密文补结束符 */
    printf("\n密文(%d字符): %s\n", clen, cipher);

    dt_decrypt(&k1, &k2, cipher, clen, dec);  /* 双重解密 */
    dec[plen] = '\0';                       /* 截掉填充字符 */
    printf("解密(%d字符): %s\n", plen, dec);

    printf("%s\n", strcmp(plain, dec) == 0 ? "[OK] 往返验证通过" : "[FAIL] 往返不一致");  /* 比较往返结果 */
    return 0;
}
