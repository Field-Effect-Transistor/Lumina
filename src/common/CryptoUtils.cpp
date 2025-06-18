// CryptoUtils.cpp (виправлена версія)

#include "CryptoUtils.hpp"

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
        // Зверніть увагу: crypto_pwhash повертає 0 при успіху
        if (crypto_pwhash(
            hash.data(),
            hash.size(),
            password.c_str(),
            password.length(),
            salt_bin.data(),
            crypto_pwhash_OPSLIMIT_SENSITIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13
        ) != 0) {
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
        try {
            auto calculated_hash_bin = hashPassword(password, hex2bin(salt_hex), hash_length);
            return bin2hex(calculated_hash_bin) == expectedHash;
        } catch (const std::runtime_error& e) {
            // Якщо hex2bin або hashPassword кидає виняток, пароль невірний
            std::cerr << "Error during password verification: " << e.what() << std::endl;
            return false;
        }
    }

    // Змінено, щоб уникнути витоків пам'яті
    std::string generateTokenBase64(int length) {
        std::vector<byte> token(length);
        randombytes_buf(token.data(), length);
        
        // Розраховуємо необхідний розмір для Base64 рядка
        size_t base64_len = sodium_base64_ENCODED_LEN(length, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        std::string token_base64(base64_len, '\0');

        sodium_bin2base64(
            &token_base64[0],
            base64_len,
            token.data(),
            length,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING
        );
        
        token_base64.pop_back(); // Видаляємо нуль-термінатор
        return token_base64;
    }

    std::vector<byte> hashTokenBin(const std::string& rawToken) {
        std::vector<byte> token_hash_bin(crypto_hash_sha256_BYTES);
        // crypto_hash_sha256 повертає 0 при успіху
        if (crypto_hash_sha256(
            token_hash_bin.data(),
            reinterpret_cast<const byte*>(rawToken.data()),
            rawToken.size()
        ) != 0) {
            throw std::runtime_error("Failed to hash token");
        }
        return token_hash_bin;
    }
    
    // Змінено, щоб уникнути витоків пам'яті
    std::string generateAccessTokenBase64(
        const boost::json::object& payload,
        const std::string& key
    ) {
        if (key.size() != crypto_aead_chacha20poly1305_IETF_KEYBYTES) {
            throw std::runtime_error("Invalid key size");
        }

        std::string payload_str = boost::json::serialize(payload);
        
        // Використовуємо вектор для безпечного керування пам'яттю
        std::vector<byte> result_bin(
            crypto_aead_chacha20poly1305_IETF_NPUBBYTES +
            payload_str.size() +
            crypto_aead_chacha20poly1305_IETF_ABYTES
        );

        byte* nonce_ptr = result_bin.data();
        randombytes_buf(nonce_ptr, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);

        byte* ciphertext_ptr = result_bin.data() + crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
        unsigned long long ciphertext_len;

        if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext_ptr, &ciphertext_len,
            reinterpret_cast<const byte*>(payload_str.data()), payload_str.size(),
            nullptr, 0, nullptr,
            nonce_ptr,
            reinterpret_cast<const byte*>(key.data())
        ) != 0) {
            throw std::runtime_error("Failed to encrypt payload");
        }
        
        // Встановлюємо фактичний розмір (nonce + ciphertext)
        result_bin.resize(crypto_aead_chacha20poly1305_IETF_NPUBBYTES + ciphertext_len);

        // Конвертація в Base64
        size_t base64_len = sodium_base64_ENCODED_LEN(result_bin.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        std::string token_base64(base64_len, '\0');
        
        sodium_bin2base64(
            &token_base64[0],
            base64_len,
            result_bin.data(),
            result_bin.size(),
            sodium_base64_VARIANT_URLSAFE_NO_PADDING
        );

        token_base64.pop_back(); // Видаляємо нуль-термінатор
        return token_base64;
    }

    std::optional<boost::json::object> validateAccessTokenBase64(
        const std::string& token_base64,
        const std::string& key
    ) {
        if (key.size() != crypto_aead_chacha20poly1305_IETF_KEYBYTES) {
            std::cerr << "[ERROR] Invalid key size." << std::endl;
            return std::nullopt;
        }
    
        if (token_base64.empty()) {
            std::cerr << "[ERROR] Input token is empty." << std::endl;
            return std::nullopt;
        }
    
        // Декодування Base64. Виділяємо буфер, який гарантовано вмістить результат.
        std::vector<byte> token_bin(token_base64.size());
        size_t actual_bin_len;
    
        if (sodium_base642bin(
            token_bin.data(), token_bin.size(),
            token_base64.c_str(), token_base64.length(),
            nullptr, &actual_bin_len, nullptr,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING
        ) != 0) {
            std::cerr << "[ERROR] Failed to decode Base64 token." << std::endl;
            return std::nullopt;
        }
        token_bin.resize(actual_bin_len);
    
        if (token_bin.size() < (crypto_aead_chacha20poly1305_IETF_NPUBBYTES + crypto_aead_chacha20poly1305_IETF_ABYTES)) {
            std::cerr << "[ERROR] Decoded token is too short." << std::endl;
            return std::nullopt;
        }
    
        const byte* nonce_ptr = token_bin.data();
        const byte* ciphertext_with_tag_ptr = token_bin.data() + crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
        size_t ciphertext_with_tag_len = token_bin.size() - crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
    
        std::vector<byte> decrypted_payload_bin(ciphertext_with_tag_len);
        unsigned long long actual_decrypted_payload_len;
    
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
                decrypted_payload_bin.data(), &actual_decrypted_payload_len,
                nullptr,
                ciphertext_with_tag_ptr, ciphertext_with_tag_len,
                nullptr, 0,
                nonce_ptr,
                reinterpret_cast<const byte*>(key.data())
            ) != 0) {
            std::cerr << "[ERROR] Decryption failed or authentication tag is invalid." << std::endl;
            return std::nullopt;
        }
    
        std::string payload_str(reinterpret_cast<const char*>(decrypted_payload_bin.data()), actual_decrypted_payload_len);
        
        boost::system::error_code ec;
        boost::json::value parsed_payload = boost::json::parse(payload_str, ec);
    
        if (ec || !parsed_payload.is_object()) {
            std::cerr << "[ERROR] Failed to parse decrypted payload as JSON." << std::endl;
            return std::nullopt;
        }
    
        return parsed_payload.as_object();
    }
}
