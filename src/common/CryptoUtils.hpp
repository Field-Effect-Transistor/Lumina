//  CryptoUtils.hpp

#pragma once

#include <string>
#include <vector>
#include <sodium.h>
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <boost/json.hpp>
#include <optional>

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
    
    inline std::vector<byte> hex2bin(const std::string& hex) {
        // Використовуємо вектор для автоматичного керування пам'яттю
        std::vector<byte> bin(hex.size() / 2);
        size_t actual_length;
        // Перевірка на успіх: функція повертає 0
        if (sodium_hex2bin(
            bin.data(),
            bin.size(),
            hex.c_str(),
            hex.size(),
            nullptr,
            &actual_length,
            nullptr
        ) != 0) {
            throw std::runtime_error("Failed to convert hex to bin. Input might be invalid.");
        }
        bin.resize(actual_length); // На випадок, якщо результат коротший
        return bin;
    }

    // `bin2hex` був у порядку, але я його перемістив сюди для послідовності
    inline std::string bin2hex(const std::vector<byte>& bin) {
        std::string hex_str(bin.size() * 2 + 1, '\0'); // +1 для нуль-термінатора
        sodium_bin2hex(
            &hex_str[0], // Безпечніший спосіб отримати неконстантний покажчик
            hex_str.size(),
            bin.data(),
            bin.size()
        );
        hex_str.pop_back(); // Видаляємо нуль-термінатор, який додав sodium
        return hex_str;
    }

    std::string generateAccessTokenBase64(
        const boost::json::object& payload,
        const std::string& key
    );

    /**
     * @brief Validates and decodes an access token represented as a Base64 string.
     *
     * @param token_base64 Access token as a Base64 string.
     * @param key Private key for decryption and authentication.
     *
     * @return Decoded payload as a JSON object if the token is valid, otherwise std::nullopt.
     *
     * @throws std::runtime_error If the key size is invalid or if the token is empty.
     *
     * This function will also print error messages to cerr if the token is invalid in any way.
     */
    std::optional<boost::json::object> validateAccessTokenBase64(
        const std::string& token,
        const std::string& key
    );
}
