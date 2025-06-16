//  CryptoUtils.cpp

#include "CryptoUtils.hpp"
#include <iomanip>

namespace CryptoUtils {
    void init(void) {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }

    std::vector<byte> saltBin(int length) {
        std::vector<byte> salt(length);
        randombytes_buf(salt.data(), salt.size());
        return salt;
    }
    
    std::vector<byte> hashPassword(
        const std::string& password,
        const std::vector<byte>& salt_bin,
        size_t hash_length
    ) {
        std::vector<byte> hash(hash_length);
        if (!crypto_pwhash(
            hash.data(),
            hash_length,
            password.data(),
            password.size(),
            salt_bin.data(),
            crypto_pwhash_OPSLIMIT_SENSITIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13
        )) {
            throw std::runtime_error("Failed to hash password");
        }
        return hash;
    }

    bool verifyPassword(
        const std::string& password,
        const std::string& salt_hex,
        const std::string& expectedHash,
        size_t hash_length
    ) {
        auto hash = hashPassword(password, hex2bin(salt_hex), hash_length);
        return CryptoUtils::bin2hex(hash) == expectedHash;  
    }

    std::string generateTokenBase64(int length = 32) {
        std::vector<byte> token(length);
        randombytes_buf(token.data(), token.size());
        std::string token_base64(
            sodium_base64_ENCODED_LEN(token.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1,  // -1 for the null terminator
            '\0'
        );
        sodium_bin2base64(
            token_base64.data(),
            token_base64.size() + 1,
            token.data(),
            token.size(),
            sodium_base64_VARIANT_URLSAFE_NO_PADDING
        );

        return token_base64;
    }

    std::vector<byte> hashTokenBin(const std::string& rawToken) {
        std::vector<byte> token_hash_bin(32);   //  constant length for sha256
        std::vector<byte> token_bin(rawToken.begin(), rawToken.end());
        if (!crypto_hash_sha256(
            token_hash_bin.data(),
            token_bin.data(),
            token_bin.size()
        )) {
            throw std::runtime_error("Failed to hash token");
        }
        return token_hash_bin;
    }
}
