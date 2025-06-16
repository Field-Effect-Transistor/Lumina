//  CryptoUtils.hpp

#pragma once

#include <string>
#include <vector>
#include <sodium.h>
#include <iostream>
#include <stdexcept>
#include <sstream>

namespace CryptoUtils {
    using byte = unsigned char;

    void init(void);
    std::vector<byte> saltBin(int length = crypto_pwhash_SALTBYTES);
    std::vector<byte> hashPassword(
        const std::string& password,
        const std::vector<byte>& salt_bin,
        size_t hash_length = 32
    );
    bool verifyPassword(
        const std::string& password,
        const std::string& salt_hex,
        const std::string& expectedHash,
        size_t hash_length = 32
    );
    std::string generateTokenBase64(int length = 32);
    std::vector<byte> hashTokenBin(const std::string& rawToken);

    inline std::string bin2hex(const std::vector<byte>& bin) {
        std::string hex_str(bin.size() * 2, '\0');
        sodium_bin2hex(
            hex_str.data(),
            bin.size() * 2 + 1,
            bin.data(),
            bin.size()
        );
        return hex_str;
    }
    inline std::vector<byte> hex2bin(const std::string& hex) {
        byte* bin = new byte[hex.size() / 2];
        char* ptr;
        size_t actual_length;
        if ( !sodium_hex2bin(
            bin,
            hex.size() / 2,
            hex.data(),
            hex.size(),
            nullptr,
            &actual_length,
            &ptr
        )) {
            throw std::runtime_error("Failed to convert hex to bin");
        }
        std::vector<byte> bin_vector(bin, bin + actual_length);
        delete[] bin;
        return bin_vector;
    }
}
