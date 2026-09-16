// wireguard.cpp —— 见 wireguard.h 的说明
//
// 原语实现全部来自公开标准，便于对照官方测试向量：
//   * BLAKE2s      : RFC 7693（附录 B 给出的 "abc" 向量）
//   * X25519       : RFC 7748（§6.1 Alice/Bob 向量）
//   * ChaCha20-Poly1305 : RFC 8439（§2.8.2 AEAD 向量）
//   * Noise IKpsk2 : WireGuard 白皮书 / WireGuard 源码 noise.c
//
// 这里刻意不做任何「聪明」的优化：全部是直白的教科书实现，
// 目的是被测速工具当作一个可核对的参照物，而不是追求吞吐。

#include "wireguard.h"

#include <string.h>
#include <stdint.h>
#include <vector>

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

// ===========================================================================
// 小工具
// ===========================================================================

static u32 load32_le(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static void store32_le(u8 *p, u32 v) {
    p[0] = (u8)(v);
    p[1] = (u8)(v >> 8);
    p[2] = (u8)(v >> 16);
    p[3] = (u8)(v >> 24);
}

// ===========================================================================
// BLAKE2s（RFC 7693）
// ===========================================================================

static const u32 BLAKE2S_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

static const u8 BLAKE2S_SIGMA[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

static const u32 BLAKE2S_BLOCKBYTES = 64;

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// 状态：h 为链值，buf 缓存未满的一块，buflen 为其中字节数，t 为已压缩字节数
struct Blake2sState {
    u32    h[8];
    u8     buf[BLAKE2S_BLOCKBYTES];
    size_t buflen;
    u64    t;
};

static void blake2s_compress(Blake2sState *S, const u8 block[BLAKE2S_BLOCKBYTES], int last) {
    u32 v[16], m[16];

    for (int i = 0; i < 16; ++i) {
        m[i] = load32_le(block + 4 * i);
    }
    for (int i = 0; i < 8; ++i) {
        v[i]     = S->h[i];
        v[i + 8] = BLAKE2S_IV[i];
    }
    v[12] ^= (u32)(S->t);
    v[13] ^= (u32)(S->t >> 32);
    if (last) {
        v[14] = ~v[14];
    }

#define B2S_G(a, b, c, d, x, y)                 \
    do {                                        \
        v[a] = v[a] + v[b] + (x);               \
        v[d] = ROTR32(v[d] ^ v[a], 16);         \
        v[c] = v[c] + v[d];                     \
        v[b] = ROTR32(v[b] ^ v[c], 12);         \
        v[a] = v[a] + v[b] + (y);               \
        v[d] = ROTR32(v[d] ^ v[a], 8);          \
        v[c] = v[c] + v[d];                     \
        v[b] = ROTR32(v[b] ^ v[c], 7);          \
    } while (0)

    for (int r = 0; r < 10; ++r) {
        const u8 *s = BLAKE2S_SIGMA[r];
        B2S_G( 0,  4,  8, 12, m[s[ 0]], m[s[ 1]]);
        B2S_G( 1,  5,  9, 13, m[s[ 2]], m[s[ 3]]);
        B2S_G( 2,  6, 10, 14, m[s[ 4]], m[s[ 5]]);
        B2S_G( 3,  7, 11, 15, m[s[ 6]], m[s[ 7]]);
        B2S_G( 0,  5, 10, 15, m[s[ 8]], m[s[ 9]]);
        B2S_G( 1,  6, 11, 12, m[s[10]], m[s[11]]);
        B2S_G( 2,  7,  8, 13, m[s[12]], m[s[13]]);
        B2S_G( 3,  4,  9, 14, m[s[14]], m[s[15]]);
    }
#undef B2S_G

    for (int i = 0; i < 8; ++i) {
        S->h[i] ^= v[i] ^ v[i + 8];
    }
}

static void blake2s_init(Blake2sState *S, size_t outlen, size_t keylen) {
    for (int i = 0; i < 8; ++i) {
        S->h[i] = BLAKE2S_IV[i];
    }
    // 参数块第 0 个字（小端）：depth(1) | fanout(1) | keylen | outlen
    S->h[0] ^= 0x01010000u ^ ((u32)keylen << 8) ^ (u32)outlen;
    S->buflen = 0;
    S->t      = 0;
}

static void blake2s_update(Blake2sState *S, const u8 *in, size_t inlen) {
    if (inlen == 0) {
        return;
    }

    size_t left = S->buflen;
    size_t fill = BLAKE2S_BLOCKBYTES - left;

    if (inlen > fill) {
        S->buflen = 0;
        memcpy(S->buf + left, in, fill);
        S->t += BLAKE2S_BLOCKBYTES;
        blake2s_compress(S, S->buf, 0);
        in    += fill;
        inlen -= fill;

        while (inlen > BLAKE2S_BLOCKBYTES) {
            S->t += BLAKE2S_BLOCKBYTES;
            blake2s_compress(S, in, 0);
            in    += BLAKE2S_BLOCKBYTES;
            inlen -= BLAKE2S_BLOCKBYTES;
        }
    }

    memcpy(S->buf + S->buflen, in, inlen);
    S->buflen += inlen;
}

static void blake2s_final(Blake2sState *S, u8 *out, size_t outlen) {
    u8 buffer[32];

    S->t += (u64)S->buflen;
    memset(S->buf + S->buflen, 0, BLAKE2S_BLOCKBYTES - S->buflen);
    blake2s_compress(S, S->buf, 1);

    for (int i = 0; i < 8; ++i) {
        store32_le(buffer + 4 * i, S->h[i]);
    }
    memcpy(out, buffer, outlen);
}

size_t wg_blake2s(unsigned char *out, size_t outlen,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *in, size_t inlen) {
    if (out == NULL || outlen == 0 || outlen > 32 || keylen > 32) {
        return 0;
    }
    if ((key == NULL && keylen != 0) || (in == NULL && inlen != 0)) {
        return 0;
    }

    Blake2sState S;
    blake2s_init(&S, outlen, keylen);

    if (keylen > 0) {
        // BLAKE2s 的带密钥模式：密钥补齐到一块，作为第一个数据块
        u8 block[BLAKE2S_BLOCKBYTES];
        memset(block, 0, sizeof(block));
        memcpy(block, key, keylen);
        blake2s_update(&S, block, BLAKE2S_BLOCKBYTES);
    }

    blake2s_update(&S, in, inlen);
    blake2s_final(&S, out, outlen);
    return outlen;
}

// 便捷封装：HASH(a || b || c)，任一指针为 NULL 即视为长度 0
static void hash_parts(u8 out[32],
                       const u8 *a, size_t alen,
                       const u8 *b, size_t blen,
                       const u8 *c, size_t clen) {
    Blake2sState S;
    blake2s_init(&S, 32, 0);
    if (a != NULL && alen) blake2s_update(&S, a, alen);
    if (b != NULL && blen) blake2s_update(&S, b, blen);
    if (c != NULL && clen) blake2s_update(&S, c, clen);
    blake2s_final(&S, out, 32);
}

// HMAC-BLAKE2s：块长 64，摘要 32。等价于 Python 的
//   hmac.new(key, data, hashlib.blake2s).digest()
// 分成两段输入是因为 Noise 里有 HMAC(key, ck || 0x02) 这种拼出来的数据。
static void hmac_blake2s(u8 out[32], const u8 *key, size_t keylen,
                         const u8 *in1, size_t in1len,
                         const u8 *in2, size_t in2len) {
    u8 k[64];
    u8 pad[64];
    u8 inner[32];

    memset(k, 0, sizeof(k));
    if (keylen > 64) {
        wg_blake2s(k, 32, NULL, 0, key, keylen);
    } else {
        memcpy(k, key, keylen);
    }

    Blake2sState S;

    for (int i = 0; i < 64; ++i) pad[i] = (u8)(k[i] ^ 0x36);
    blake2s_init(&S, 32, 0);
    blake2s_update(&S, pad, 64);
    if (in1 != NULL && in1len) blake2s_update(&S, in1, in1len);
    if (in2 != NULL && in2len) blake2s_update(&S, in2, in2len);
    blake2s_final(&S, inner, 32);

    for (int i = 0; i < 64; ++i) pad[i] = (u8)(k[i] ^ 0x5c);
    blake2s_init(&S, 32, 0);
    blake2s_update(&S, pad, 64);
    blake2s_update(&S, inner, 32);
    blake2s_final(&S, out, 32);
}

// ===========================================================================
// X25519（RFC 7748）—— 16 个 64 位 limb 的域元素表示
// ===========================================================================

typedef int64_t fe[16];

// 2^255 - 19 的另一种写法：用 (2^16-?) 的形式做进位
static const fe FE_121665 = { 0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

// 把 fe 里的系数压回 [0, 2^16)，溢出的部分按 2^255 = 19 折回来
static void fe_carry(fe o) {
    for (int i = 0; i < 16; ++i) {
        o[i] += ((int64_t)1 << 16);
        int64_t c = o[i] >> 16;
        if (i < 15) {
            o[i + 1] += c - 1;
        } else {
            // i == 15 时下标回绕到 0，并且乘上 19（2^255 = 19 mod p）：
            // 基础项 c-1 与 38*(c-1) 相加正好是 38*(c-1)
            o[0] += 38 * (c - 1);
        }
        o[i] -= c << 16;
    }
}

static void fe_cswap(fe p, fe q, int b) {
    int64_t mask = ~(int64_t)(b - 1); // b==1 -> 全 1（交换）；b==0 -> 全 0（不动）
    for (int i = 0; i < 16; ++i) {
        int64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void fe_add(fe o, const fe a, const fe b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

static void fe_sub(fe o, const fe a, const fe b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

static void fe_mul(fe o, const fe a, const fe b) {
    int64_t t[31];
    for (int i = 0; i < 31; ++i) t[i] = 0;
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j) {
            t[i + j] += a[i] * b[j];
        }
    }
    for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    fe_carry(o);
    fe_carry(o);
}

static void fe_sq(fe o, const fe a) { fe_mul(o, a, a); }

// 把 fe 打包成 32 字节小端，并做模 p 归一化
static void fe_pack(u8 *o, const fe n) {
    fe t, m;

    for (int i = 0; i < 16; ++i) t[i] = n[i];
    fe_carry(t);
    fe_carry(t);
    fe_carry(t);

    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int64_t b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        fe_cswap(t, m, 1 - (int)b);
    }

    for (int i = 0; i < 16; ++i) {
        o[2 * i]     = (u8)(t[i] & 0xff);
        o[2 * i + 1] = (u8)(t[i] >> 8);
    }
}

static void fe_unpack(fe o, const u8 *n) {
    for (int i = 0; i < 16; ++i) {
        o[i] = (int64_t)n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    }
    o[15] &= 0x7fff;
}

static void fe_inv(fe o, const fe i) {
    fe c;
    for (int a = 0; a < 16; ++a) c[a] = i[a];
    for (int a = 253; a >= 0; --a) {
        fe_sq(c, c);
        if (a != 2 && a != 4) fe_mul(c, c, i);
    }
    for (int a = 0; a < 16; ++a) o[a] = c[a];
}

bool wg_x25519(unsigned char out[32],
               const unsigned char scalar[32],
               const unsigned char point[32]) {
    u8 z[32];
    fe x, a, b, c, d, e, f;

    for (int i = 0; i < 31; ++i) z[i] = scalar[i];
    z[31] = (u8)((scalar[31] & 127) | 64);
    z[0] &= 248;

    fe_unpack(x, point);

    for (int i = 0; i < 16; ++i) {
        b[i] = x[i];
        a[i] = c[i] = d[i] = 0;
    }
    a[0] = d[0] = 1;

    for (int i = 254; i >= 0; --i) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        fe_cswap(a, b, r);
        fe_cswap(c, d, r);
        fe_add(e, a, c);
        fe_sub(a, a, c);
        fe_add(c, b, d);
        fe_sub(b, b, d);
        fe_sq(d, e);
        fe_sq(f, a);
        fe_mul(a, c, a);
        fe_mul(c, b, e);
        fe_add(e, a, c);
        fe_sub(a, a, c);
        fe_sq(b, a);
        fe_sub(c, d, f);
        fe_mul(a, c, FE_121665);
        fe_add(a, a, d);
        fe_mul(c, c, a);
        fe_mul(a, d, f);
        fe_mul(d, b, x);
        fe_sq(b, e);
        fe_cswap(a, b, r);
        fe_cswap(c, d, r);
    }

    fe_inv(c, c);
    fe_mul(a, a, c);
    fe_pack(out, a);

    // 结果为全零说明对端是低阶点，DH 无效
    u8 zero = 0;
    for (int i = 0; i < 32; ++i) zero |= out[i];
    return zero != 0;
}

void wg_public_key(unsigned char out[32], const unsigned char priv[32]) {
    static const unsigned char basepoint[32] = { 9 };
    if (!wg_x25519(out, priv, basepoint)) {
        memset(out, 0, 32);
    }
}

// ===========================================================================
// ChaCha20 / Poly1305 / AEAD（RFC 8439）
// ===========================================================================

static u32 rotl32(u32 v, int c) {
    return (v << c) | (v >> (32 - c));
}

static void chacha20_block(const u8 key[32], const u8 nonce[12], u32 counter, u8 out[64]) {
    u32 st[16], x[16];

    st[0] = 0x61707865u;
    st[1] = 0x3320646eu;
    st[2] = 0x79622d32u;
    st[3] = 0x6b206574u;
    for (int i = 0; i < 8; ++i) {
        st[4 + i] = load32_le(key + 4 * i);
    }
    st[12] = counter;
    for (int i = 0; i < 3; ++i) {
        st[13 + i] = load32_le(nonce + 4 * i);
    }

    memcpy(x, st, sizeof(x));

#define CHACHA_QR(a, b, c, d)            \
    do {                                 \
        a += b; d ^= a; d = rotl32(d, 16); \
        c += d; b ^= c; b = rotl32(b, 12); \
        a += b; d ^= a; d = rotl32(d, 8);  \
        c += d; b ^= c; b = rotl32(b, 7);  \
    } while (0)

    for (int i = 0; i < 10; ++i) {
        CHACHA_QR(x[0], x[4], x[ 8], x[12]);
        CHACHA_QR(x[1], x[5], x[ 9], x[13]);
        CHACHA_QR(x[2], x[6], x[10], x[14]);
        CHACHA_QR(x[3], x[7], x[11], x[15]);
        CHACHA_QR(x[0], x[5], x[10], x[15]);
        CHACHA_QR(x[1], x[6], x[11], x[12]);
        CHACHA_QR(x[2], x[7], x[ 8], x[13]);
        CHACHA_QR(x[3], x[4], x[ 9], x[14]);
    }
#undef CHACHA_QR

    for (int i = 0; i < 16; ++i) {
        store32_le(out + 4 * i, x[i] + st[i]);
    }
}

static void chacha20_xor(const u8 key[32], const u8 nonce[12], u32 counter,
                         const u8 *in, size_t len, u8 *out) {
    u8 ks[64];
    size_t off = 0;

    while (off < len) {
        chacha20_block(key, nonce, counter, ks);
        ++counter;
        size_t n = len - off;
        if (n > 64) n = 64;
        for (size_t i = 0; i < n; ++i) {
            out[off + i] = (u8)(in[off + i] ^ ks[i]);
        }
        off += n;
    }
}

// Poly1305：5 个 26 位 limb，消息一次性传入（本工具的报文都很小）
static void poly1305_mac(u8 mac[16], const u8 key[32], const u8 *m, size_t len) {
    u32 r0, r1, r2, r3, r4, s1, s2, s3, s4;
    u32 h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    u32 pad0, pad1, pad2, pad3;

    r0 = load32_le(key + 0)  & 0x3ffffffu;
    r1 = load32_le(key + 3)  >> 2;
    r2 = load32_le(key + 6)  >> 4;
    r3 = load32_le(key + 9)  >> 6;
    r4 = load32_le(key + 12) >> 8;

    r1 &= 0x3ffff03u;
    r2 &= 0x3ffc0ffu;
    r3 &= 0x3f03fffu;
    r4 &= 0x00fffffu;

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    pad0 = load32_le(key + 16);
    pad1 = load32_le(key + 20);
    pad2 = load32_le(key + 24);
    pad3 = load32_le(key + 28);

    // 一块消息的处理：先 h += 消息，再 h *= r，最后部分约减
#define POLY_BLOCK(t0, t1, t2, t3, t4)                                              \
    do {                                                                            \
        h0 += (t0); h1 += (t1); h2 += (t2); h3 += (t3); h4 += (t4);                 \
        u64 d0 = (u64)h0 * r0 + (u64)h1 * s4 + (u64)h2 * s3 + (u64)h3 * s2 + (u64)h4 * s1; \
        u64 d1 = (u64)h0 * r1 + (u64)h1 * r0 + (u64)h2 * s4 + (u64)h3 * s3 + (u64)h4 * s2; \
        u64 d2 = (u64)h0 * r2 + (u64)h1 * r1 + (u64)h2 * r0 + (u64)h3 * s4 + (u64)h4 * s3; \
        u64 d3 = (u64)h0 * r3 + (u64)h1 * r2 + (u64)h2 * r1 + (u64)h3 * r0 + (u64)h4 * s4; \
        u64 d4 = (u64)h0 * r4 + (u64)h1 * r3 + (u64)h2 * r2 + (u64)h3 * r1 + (u64)h4 * r0; \
        u32 cc;                                                                     \
        cc = (u32)(d0 >> 26); h0 = (u32)d0 & 0x3ffffffu; d1 += cc;                   \
        cc = (u32)(d1 >> 26); h1 = (u32)d1 & 0x3ffffffu; d2 += cc;                   \
        cc = (u32)(d2 >> 26); h2 = (u32)d2 & 0x3ffffffu; d3 += cc;                   \
        cc = (u32)(d3 >> 26); h3 = (u32)d3 & 0x3ffffffu; d4 += cc;                   \
        cc = (u32)(d4 >> 26); h4 = (u32)d4 & 0x3ffffffu; h0 += cc * 5;               \
        cc = h0 >> 26;        h0 &= 0x3ffffffu;          h1 += cc;                   \
    } while (0)

    while (len >= 16) {
        POLY_BLOCK(load32_le(m + 0)  & 0x3ffffffu,
                   (load32_le(m + 3)  >> 2) & 0x3ffffffu,
                   (load32_le(m + 6)  >> 4) & 0x3ffffffu,
                   (load32_le(m + 9)  >> 6) & 0x3ffffffu,
                   (load32_le(m + 12) >> 8) | (1u << 24)); // 隐含的 2^128 位
        m   += 16;
        len -= 16;
    }

    if (len > 0) {
        // 末尾不足一块：补一个 0x01 字节，其余补零，并且没有隐含的 2^128 位
        u8 buf[16];
        memset(buf, 0, sizeof(buf));
        memcpy(buf, m, len);
        buf[len] = 1;
        POLY_BLOCK(load32_le(buf + 0)  & 0x3ffffffu,
                   (load32_le(buf + 3)  >> 2) & 0x3ffffffu,
                   (load32_le(buf + 6)  >> 4) & 0x3ffffffu,
                   (load32_le(buf + 9)  >> 6) & 0x3ffffffu,
                   (load32_le(buf + 12) >> 8));
    }
#undef POLY_BLOCK

    // 完全进位
    u32 cc;
    cc = h1 >> 26; h1 &= 0x3ffffffu;
    h2 += cc;      cc = h2 >> 26; h2 &= 0x3ffffffu;
    h3 += cc;      cc = h3 >> 26; h3 &= 0x3ffffffu;
    h4 += cc;      cc = h4 >> 26; h4 &= 0x3ffffffu;
    h0 += cc * 5;  cc = h0 >> 26; h0 &= 0x3ffffffu;
    h1 += cc;

    // 计算 h + (2^130 - 5)，即 h - p 的补形式
    u32 g0 = h0 + 5; cc = g0 >> 26; g0 &= 0x3ffffffu;
    u32 g1 = h1 + cc; cc = g1 >> 26; g1 &= 0x3ffffffu;
    u32 g2 = h2 + cc; cc = g2 >> 26; g2 &= 0x3ffffffu;
    u32 g3 = h3 + cc; cc = g3 >> 26; g3 &= 0x3ffffffu;
    u32 g4 = h4 + cc - (1u << 26);

    // g4 的最高位为 1（下溢）说明 h < p，此时保留 h
    u32 mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    // 取模 2^128
    h0 = (h0 | (h1 << 26)) & 0xffffffffu;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffffu;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffu;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffffu;

    // mac = (h + pad) mod 2^128
    u64 f;
    f = (u64)h0 + pad0;            h0 = (u32)f;
    f = (u64)h1 + pad1 + (f >> 32); h1 = (u32)f;
    f = (u64)h2 + pad2 + (f >> 32); h2 = (u32)f;
    f = (u64)h3 + pad3 + (f >> 32); h3 = (u32)f;

    store32_le(mac + 0,  h0);
    store32_le(mac + 4,  h1);
    store32_le(mac + 8,  h2);
    store32_le(mac + 12, h3);
}

bool wg_aead_encrypt(unsigned char *out,
                     const unsigned char key[32],
                     unsigned long long counter,
                     const unsigned char *msg, size_t msglen,
                     const unsigned char *aad, size_t aadlen) {
    u8 nonce[12];
    u8 polykey[64];

    if (out == NULL || key == NULL) return false;
    if (msg == NULL && msglen != 0) return false;
    if (aad == NULL && aadlen != 0) return false;

    nonce[0] = nonce[1] = nonce[2] = nonce[3] = 0;
    for (int i = 0; i < 8; ++i) {
        nonce[4 + i] = (u8)(counter >> (8 * i));
    }

    // counter 0 的密钥流前 32 字节就是 Poly1305 的一次性密钥
    chacha20_block(key, nonce, 0, polykey);
    // 真正的加密从 counter 1 开始
    chacha20_xor(key, nonce, 1, msg, msglen, out);

    // MAC 输入：aad || pad16 || ct || pad16 || le64(aadlen) || le64(ctlen)
    size_t aadpad = (16 - (aadlen % 16)) % 16;
    size_t ctpad  = (16 - (msglen % 16)) % 16;

    std::vector<u8> buf(aadlen + aadpad + msglen + ctpad + 16, 0);
    size_t off = 0;
    if (aadlen) { memcpy(&buf[off], aad, aadlen); off += aadlen; }
    off += aadpad;
    if (msglen) { memcpy(&buf[off], out, msglen); off += msglen; }
    off += ctpad;
    for (int i = 0; i < 8; ++i) buf[off + i]     = (u8)((u64)aadlen >> (8 * i));
    for (int i = 0; i < 8; ++i) buf[off + 8 + i] = (u8)((u64)msglen >> (8 * i));

    poly1305_mac(out + msglen, polykey, &buf[0], buf.size());
    return true;
}

// ===========================================================================
// WireGuard 握手发起包
// ===========================================================================

static const char WG_CONSTRUCTION[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char WG_IDENTIFIER[]   = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const char WG_LABEL_MAC1[]   = "mac1----";

bool wg_build_handshake_initiation(unsigned char *out,
                                   const unsigned char static_priv[32],
                                   const unsigned char responder_pub[32],
                                   const unsigned char reserved[3],
                                   const unsigned char eph_priv[32],
                                   unsigned int sender_index,
                                   unsigned long long unix_nanos) {
    if (out == NULL || static_priv == NULL || responder_pub == NULL ||
        reserved == NULL || eph_priv == NULL) {
        return false;
    }

    u8 static_pub[32], eph_pub[32];
    u8 ck[32], h[32], tmp[32], key[32], dh[32], inner[32];
    u8 enc_static[48], enc_ts[28];
    const u8 one = 0x01, two = 0x02;

    // ---- 初始化握手状态 ----
    // ck = HASH(CONSTRUCTION)
    hash_parts(ck, (const u8 *)WG_CONSTRUCTION, sizeof(WG_CONSTRUCTION) - 1, NULL, 0, NULL, 0);
    // h  = HASH(HASH(ck || IDENTIFIER) || responder_pub)
    hash_parts(inner, ck, 32, (const u8 *)WG_IDENTIFIER, sizeof(WG_IDENTIFIER) - 1, NULL, 0);
    hash_parts(h, inner, 32, responder_pub, 32, NULL, 0);

    // ---- 加入临时公钥，做第一轮 DH ----
    wg_public_key(static_pub, static_priv);
    wg_public_key(eph_pub, eph_priv);

    // h = HASH(h || eph_pub)
    hash_parts(h, h, 32, eph_pub, 32, NULL, 0);

    // ck = KDF1(ck, eph_pub)
    hmac_blake2s(tmp, ck, 32, eph_pub, 32, NULL, 0);
    hmac_blake2s(ck, tmp, 32, &one, 1, NULL, 0);

    // ---- 加密静态公钥（Noise IK 的第 1 个 payload）----
    if (!wg_x25519(dh, eph_priv, responder_pub)) return false;
    hmac_blake2s(tmp, ck, 32, dh, 32, NULL, 0);       // tmp = KDF1
    hmac_blake2s(ck, tmp, 32, &one, 1, NULL, 0);      // ck  = KDF1
    hmac_blake2s(key, tmp, 32, ck, 32, &two, 1);      // key = KDF2

    wg_aead_encrypt(enc_static, key, 0, static_pub, 32, h, 32);
    hash_parts(h, h, 32, enc_static, 48, NULL, 0);

    // ---- 加密时间戳（Noise IK 的第 2 个 payload）----
    if (!wg_x25519(dh, static_priv, responder_pub)) return false;
    hmac_blake2s(tmp, ck, 32, dh, 32, NULL, 0);
    hmac_blake2s(ck, tmp, 32, &one, 1, NULL, 0);
    hmac_blake2s(key, tmp, 32, ck, 32, &two, 1);

    // TAI64N：8 字节大端「秒 + 2^62 + 10」，4 字节大端微秒
    u64 secs = unix_nanos / 1000000000ULL + (1ULL << 62) + 10ULL;
    u32 nsec = (u32)((unix_nanos % 1000000000ULL) / 1000ULL);

    u8 ts[12];
    for (int i = 0; i < 8; ++i) ts[i]     = (u8)(secs >> (8 * (7 - i)));
    for (int i = 0; i < 4; ++i) ts[8 + i] = (u8)(nsec >> (8 * (3 - i)));

    wg_aead_encrypt(enc_ts, key, 0, ts, 12, h, 32);

    // ---- 拼装 148 字节报文 ----
    out[0] = WG_MSG_HANDSHAKE_INITIATION;
    out[1] = reserved[0];
    out[2] = reserved[1];
    out[3] = reserved[2];
    store32_le(out + 4, sender_index);
    memcpy(out + 8,   eph_pub,    32);
    memcpy(out + 40,  enc_static, 48);
    memcpy(out + 88,  enc_ts,     28);

    // mac1 = MAC(HASH(LABEL_MAC1 || responder_pub), 前 116 字节)
    u8 label_hash[32];
    hash_parts(label_hash, (const u8 *)WG_LABEL_MAC1, sizeof(WG_LABEL_MAC1) - 1,
               responder_pub, 32, NULL, 0);
    wg_blake2s(out + 116, 16, label_hash, 32, out, 116);

    // mac2 留零（只有在服务端发过 cookie 之后才需要填）
    memset(out + 132, 0, 16);

    return true;
}
