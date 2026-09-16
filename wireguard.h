// wireguard.h
//
// 极简自包含 WireGuard 握手实现（C++11，无第三方依赖）。
//
// 只实现「握手发起包」的组装，外加它需要的密码学原语：
//   * X25519（Curve25519 ECDH）
//   * BLAKE2s-256（Noise 的 HASH）
//   * HMAC-BLAKE2s（Noise 的 HMAC，块长 64）
//   * 带密钥的 BLAKE2s-128（WireGuard 的 MAC，用于 mac1）
//   * ChaCha20-Poly1305 AEAD（Noise 的 ENCRYPT，12 字节 nonce = 4 零字节 + 8 字节小端计数）
//
// 用途：探测某个 UDP 端点是不是真的 WireGuard 服务端。
// 服务端只有在 mac1 校验通过、encrypted_static 能在自己的 peer 表里找到、
// 且时间戳有效时才会回一个 148 字节的握手响应（类型 0x02）。
// 因此「收到 0x02」就是端点确实是 WireGuard 且有我们的 peer 的铁证。

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// WireGuard 握手发起包固定 148 字节
#define WG_HANDSHAKE_LEN 148

// WireGuard 报文类型（首字节）
#define WG_MSG_HANDSHAKE_INITIATION 1
#define WG_MSG_HANDSHAKE_RESPONSE   2
#define WG_MSG_COOKIE_REPLY         3
#define WG_MSG_TRANSPORT_DATA       4

// WARP 服务端公钥（engage.cloudflareclient.com 的 peer public key）
#define WG_WARP_PEER_KEY_B64 "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

// TAI64N 秒的固定偏移：2^62 + 10
#define WG_TAI64N_OFFSET 4611686018427387914ULL

// ---------------------------------------------------------------------------
// 密码学原语（也导出给测试用，便于对着 RFC 官方向量自检）
// ---------------------------------------------------------------------------

// BLAKE2s 单向哈希。outlen 1..32；key 为 NULL/keylen 0 表示不带密钥。
// 返回写入 out 的字节数（失败返回 0）。
size_t wg_blake2s(unsigned char *out, size_t outlen,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *in, size_t inlen);

// X25519：out = scalar * point。point 全零或结果为全零（低阶点）返回 false。
bool wg_x25519(unsigned char out[32],
               const unsigned char scalar[32],
               const unsigned char point[32]);

// ChaCha20-Poly1305 AEAD 加密（RFC 8439）。
// counter 是 WireGuard 的 64 位计数器，落在 nonce 的后 8 字节（小端）。
// 输出长度为 msglen + 16（密文 || tag）。
bool wg_aead_encrypt(unsigned char *out,
                     const unsigned char key[32],
                     unsigned long long counter,
                     const unsigned char *msg, size_t msglen,
                     const unsigned char *aad, size_t aadlen);

// ---------------------------------------------------------------------------
// WireGuard 组装
// ---------------------------------------------------------------------------

// 由 32 字节原始私钥算出 32 字节公钥（X25519 基点 9）
void wg_public_key(unsigned char out[32], const unsigned char priv[32]);

// 组装一个 148 字节的握手发起包。
//
//   out            输出缓冲，必须 >= WG_HANDSHAKE_LEN
//   static_priv    本端静态私钥（注册 WARP 拿到的那把，32 字节）
//   responder_pub  对端公钥（WARP 用 WG_WARP_PEER_KEY_B64 解出来的 32 字节）
//   reserved       3 字节保留字段。WARP 实测：握手发起必须用 {0,0,0}，
//                  注册时的 client_id 只用于数据包，不能填在这里。
//   eph_priv       本次握手的临时私钥（32 字节）。同一个包可以打给所有目标。
//   sender_index   4 字节小端 index，仅用于匹配响应
//   unix_nanos     当前 Unix 时间（纳秒），内部换算成 TAI64N
//
// 成功返回 true。任一指针为 NULL、或某次 DH 算出全零（对端是低阶点）时返回 false。
bool wg_build_handshake_initiation(unsigned char *out,
                                   const unsigned char static_priv[32],
                                   const unsigned char responder_pub[32],
                                   const unsigned char reserved[3],
                                   const unsigned char eph_priv[32],
                                   unsigned int sender_index,
                                   unsigned long long unix_nanos);

#ifdef __cplusplus
}
#endif

#endif // WIREGUARD_H
