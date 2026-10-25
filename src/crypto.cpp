// crypto.cpp - SHA-256 (FIPS 180-4), HMAC (RFC 2104), PBKDF2 (RFC 8018).
#include "crypto.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cstring>
#include <stdexcept>

namespace crypto {
namespace {
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void block(uint32_t h[8], const uint8_t* p) {
  uint32_t w[64];
  for (int i = 0; i < 16; ++i)
    w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
  for (int i = 16; i < 64; ++i) {
    uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
  for (int i = 0; i < 64; ++i) {
    uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = k + S1 + ch + K[i] + w[i];
    uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + mj;
    k = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
}
}  // namespace

std::vector<uint8_t> sha256(const uint8_t* data, size_t n) {
  uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  size_t full = n / 64;
  for (size_t i = 0; i < full; ++i) block(h, data + 64 * i);
  uint8_t tail[128] = {0};
  size_t rem = n - 64 * full;
  memcpy(tail, data + 64 * full, rem);
  tail[rem] = 0x80;
  size_t tl = rem + 1 + 8 <= 64 ? 64 : 128;
  uint64_t bits = (uint64_t)n * 8;
  for (int i = 0; i < 8; ++i) tail[tl - 1 - i] = (uint8_t)(bits >> (8 * i));
  block(h, tail);
  if (tl == 128) block(h, tail + 64);
  std::vector<uint8_t> out(32);
  for (int i = 0; i < 8; ++i) {
    out[4 * i] = (uint8_t)(h[i] >> 24);
    out[4 * i + 1] = (uint8_t)(h[i] >> 16);
    out[4 * i + 2] = (uint8_t)(h[i] >> 8);
    out[4 * i + 3] = (uint8_t)h[i];
  }
  return out;
}

std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const uint8_t* data, size_t n) {
  std::vector<uint8_t> k = key.size() > 64 ? sha256(key.data(), key.size()) : key;
  k.resize(64, 0);
  std::vector<uint8_t> inner(64 + n), outer(64 + 32);
  for (int i = 0; i < 64; ++i) {
    inner[i] = k[i] ^ 0x36;
    outer[i] = k[i] ^ 0x5c;
  }
  if (n) memcpy(inner.data() + 64, data, n);
  std::vector<uint8_t> ih = sha256(inner.data(), inner.size());
  memcpy(outer.data() + 64, ih.data(), 32);
  return sha256(outer.data(), outer.size());
}

std::vector<uint8_t> pbkdf2_sha256(const std::string& password, const std::vector<uint8_t>& salt, unsigned iterations,
                                   size_t out_len) {
  std::vector<uint8_t> key(password.begin(), password.end());
  std::vector<uint8_t> out;
  for (uint32_t blockno = 1; out.size() < out_len; ++blockno) {
    std::vector<uint8_t> s = salt;
    for (int i = 3; i >= 0; --i) s.push_back((uint8_t)(blockno >> (8 * i)));
    std::vector<uint8_t> u = hmac_sha256(key, s.data(), s.size()), t = u;
    for (unsigned it = 1; it < iterations; ++it) {
      u = hmac_sha256(key, u.data(), u.size());
      for (size_t j = 0; j < t.size(); ++j) t[j] ^= u[j];
    }
    out.insert(out.end(), t.begin(), t.end());
  }
  out.resize(out_len);
  return out;
}

std::vector<uint8_t> random_bytes(size_t n) {
  std::vector<uint8_t> v(n);
  int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  size_t got = 0;
  while (fd >= 0 && got < n) {
    ssize_t k = read(fd, v.data() + got, n - got);
    if (k <= 0) break;
    got += (size_t)k;
  }
  if (fd >= 0) close(fd);
  if (got < n) throw std::runtime_error("cannot read /dev/urandom");
  return v;
}

std::string to_hex(const std::vector<uint8_t>& v) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (uint8_t b : v) { s += d[b >> 4]; s += d[b & 15]; }
  return s;
}

std::vector<uint8_t> from_hex(const std::string& s) {
  std::vector<uint8_t> v;
  auto val = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i + 1 < s.size(); i += 2) {
    int a = val(s[i]), b = val(s[i + 1]);
    if (a < 0 || b < 0) return {};
    v.push_back((uint8_t)(a * 16 + b));
  }
  return v;
}

bool equal_ct(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
  if (a.size() != b.size()) return false;
  uint8_t d = 0;
  for (size_t i = 0; i < a.size(); ++i) d |= a[i] ^ b[i];
  return d == 0;
}
}  // namespace crypto
