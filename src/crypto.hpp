// crypto.hpp - SHA-256, HMAC-SHA-256 and PBKDF2 for password hashing
// (Deliverable 4).  Self-contained so the shell needs no external library.
//
// Passwords are never stored: the user database keeps a random 16-byte salt
// and PBKDF2-HMAC-SHA256(password, salt, iterations) - a slow, salted hash,
// so a stolen database cannot be checked against a precomputed table and
// every guess costs `iterations` HMAC computations.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace crypto {
std::vector<uint8_t> sha256(const uint8_t* data, size_t n);
std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const uint8_t* data, size_t n);
std::vector<uint8_t> pbkdf2_sha256(const std::string& password, const std::vector<uint8_t>& salt,
                                   unsigned iterations, size_t out_len = 32);
std::vector<uint8_t> random_bytes(size_t n);   // from /dev/urandom
std::string to_hex(const std::vector<uint8_t>& v);
std::vector<uint8_t> from_hex(const std::string& s);
bool equal_ct(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);   // constant time
}  // namespace crypto
