//  CryptoUtils.cpp

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

    std::string generateTokenBase64(int length) {
        byte* token = new byte[length];
        randombytes_buf(token, length);
        std::string token_base64(
            sodium_base64_ENCODED_LEN(length, sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1,  // -1 for the null terminator
            '\0'
        );
        if (!sodium_bin2base64(
            token_base64.data(),
            token_base64.size() + 1,
            token,
            length,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING
        )) {
            throw std::runtime_error("Failed to generate token");
        }
        delete[] token;
        return token_base64;
    }

    std::vector<byte> hashTokenBin(const std::string& rawToken) {
        std::vector<byte> token_hash_bin(32);   //  constant length for sha256
        if (!crypto_hash_sha256(
            token_hash_bin.data(),
            reinterpret_cast<const byte*>(rawToken.data()),
            rawToken.size()
        )) {
            throw std::runtime_error("Failed to hash token");
        }
        return token_hash_bin;
    }

    std::string generateAccessTokenBase64(
        const boost::json::object& payload,
        const std::string& key
    ) {
        if (key.size() != crypto_aead_chacha20poly1305_IETF_KEYBYTES) {
            throw std::runtime_error("Invalid key size");
        }

        std::string payload_str = boost::json::serialize(payload);
        
        byte *result = new byte[
            crypto_aead_chacha20poly1305_IETF_NPUBBYTES +
            payload_str.size() +
            crypto_aead_chacha20poly1305_IETF_ABYTES
        ];

        byte *nonce = result;
        randombytes_buf(nonce, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);

        byte *c = nonce + crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
        unsigned long long c_len;

        if (!crypto_aead_chacha20poly1305_ietf_encrypt(
            c,
            &c_len,
            reinterpret_cast<const byte*>(payload_str.data()),
            payload_str.size(),
            nullptr,
            0,
            nullptr,
            nonce,
            reinterpret_cast<const byte*>(key.data())
        )) {
            throw std::runtime_error("Failed to encrypt payload");
        }

        size_t length = c_len + crypto_aead_chacha20poly1305_IETF_NPUBBYTES;

        std::string token_base64(
            sodium_base64_ENCODED_LEN(length, sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1,  // -1 for the null terminator
            '\0'
        );
        if (!sodium_bin2base64(
            token_base64.data(),
            token_base64.size() + 1,
            result,
            length,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING
        )) {
            throw std::runtime_error("Failed to generate token");
        }
        delete[] result;
        return token_base64;
    }

    std::optional<boost::json::object> validateAccessTokenBase64(
        const std::string& token_base64,
        const std::string& key
    ) {
        // 1. Перевірка розміру ключа
        if (key.size() != crypto_aead_chacha20poly1305_IETF_KEYBYTES) {
            std::cerr << "[ERROR] validateAccessTokenBase64: Invalid key size." << std::endl;
            return std::nullopt;
        }
    
        if (token_base64.empty()) {
            std::cerr << "[ERROR] validateAccessTokenBase64: Input token is empty." << std::endl;
            return std::nullopt;
        }
    
        // 2. Декодування Base64 токена в бінарні дані (nonce + шифротекст_з_тегом)
        // Розраховуємо достатній розмір буфера для бінарних даних.
        // Кожні 4 символи Base64 дають 3 байти.
        // Якщо довжина token_base64 не кратна 4, це може бути проблемою,
        // але sodium_base642bin може це обробити або повернути помилку.
        // Ми виділимо буфер з розрахунку (token_base64.length() * 3) / 4,
        // що є точним для валідного Base64 без зайвих символів.
        // Можна додати трохи запасу, якщо є сумніви, але зазвичай це не потрібно.
        // Якщо token_base64.length() < 4, то (token_base64.length() * 3) / 4 буде 0, 1 або 2.
        // sodium_base642bin поверне помилку, якщо рядок не є валідним Base64.
    
        size_t bin_maxlen;
        if (token_base64.length() == 0) { // Ще раз перевірка, хоча вже є вище
            bin_maxlen = 0;
        } else {
            // Це обчислення дає точну кількість байт, яку займають дані, закодовані в Base64,
            // якщо Base64 рядок валідний і не містить зайвих символів.
            // Наприклад, для 4 символів Base64 -> 3 байти, для 8 -> 6 байт.
            // `sodium_base64_VARIANT_URLSAFE_NO_PADDING` не використовує padding, тому довжина
            // не завжди буде кратна 4.
            // Простіший і безпечніший підхід - виділити трохи більше, ніж мінімально необхідно,
            // і покладатися на actual_bin_len.
            // Максимально можлива довжина після декодування:
            bin_maxlen = (token_base64.length() * 3) / 4 + (token_base64.length() % 4 != 0); // Груба оцінка зверху
            // Або просто:
            // bin_maxlen = token_base64.length(); // Гарантовано достатньо, але може бути забагато.
            // Давайте використаємо рекомендований підхід з документації libsodium
            // (хоча там для strlen(b64), а у нас token_base64.length())
            // Для варіанту без padding, довжина може бути не кратна 4.
            // `sodium_base642bin` сам розбереться з довжиною.
            // Ми просто повинні надати буфер, який гарантовано вмістить результат.
            // Якщо `bin_maxlen` буде точним, то `actual_bin_len` буде йому дорівнювати.
            // Якщо `bin_maxlen` буде більшим, `actual_bin_len` покаже реальний розмір.
            // (token_base64.length() * 6 + 7) / 8 - це ще одна формула для максимальної довжини Base64 -> бінарні.
            // Найпростіше - виділити буфер того ж розміру, що й вхідний рядок Base64,
            // це гарантовано буде достатньо, оскільки бінарні дані завжди коротші або рівні (для порожнього рядка).
            bin_maxlen = token_base64.length();
        }
        
        if (bin_maxlen == 0 && !token_base64.empty()) {
             std::cerr << "[ERROR] validateAccessTokenBase64: Calculated bin_maxlen is 0 for non-empty token." << std::endl;
             return std::nullopt;
        }
    
    
        std::vector<byte> token_bin(bin_maxlen); // Виділяємо буфер
        size_t actual_bin_len;
    
        int b64_result = sodium_base642bin(
            token_bin.data(),
            token_bin.size(),      // Передаємо розмір виділеного буфера
            token_base64.c_str(),
            token_base64.length(),
            nullptr,               // ignore_characters
            &actual_bin_len,
            nullptr,               // end_ptr
            sodium_base64_VARIANT_URLSAFE_NO_PADDING
        );
    
        if (b64_result != 0) {
            std::cerr << "[ERROR] validateAccessTokenBase64: Failed to decode Base64 token. Result: " << b64_result << std::endl;
            return std::nullopt;
        }
        token_bin.resize(actual_bin_len); // Встановлюємо реальний розмір вектора
    
        // 3. Перевірка мінімальної довжини бінарного токена
        if (token_bin.size() < (crypto_aead_chacha20poly1305_IETF_NPUBBYTES + crypto_aead_chacha20poly1305_IETF_ABYTES)) {
            std::cerr << "[ERROR] validateAccessTokenBase64: Decoded token is too short (size: " << token_bin.size() << ")." << std::endl;
            return std::nullopt;
        }
    
        // 4. Розділення бінарних даних на nonce та шифротекст_з_тегом
        const byte* nonce_ptr = token_bin.data();
        const byte* ciphertext_with_tag_ptr = token_bin.data() + crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
        size_t ciphertext_with_tag_len = token_bin.size() - crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
    
        // 5. Підготовка буфера для розшифрованого payload
        if (ciphertext_with_tag_len < crypto_aead_chacha20poly1305_IETF_ABYTES) {
            std::cerr << "[ERROR] validateAccessTokenBase64: Ciphertext with tag is too short." << std::endl;
            return std::nullopt;
        }
        size_t max_decrypted_payload_len = ciphertext_with_tag_len - crypto_aead_chacha20poly1305_IETF_ABYTES;
        std::vector<byte> decrypted_payload_bin(max_decrypted_payload_len);
        unsigned long long actual_decrypted_payload_len;
    
        // 6. Дешифрування та перевірка автентичності
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
                decrypted_payload_bin.data(),
                &actual_decrypted_payload_len,
                nullptr,
                ciphertext_with_tag_ptr,
                ciphertext_with_tag_len,
                nullptr,
                0,
                nonce_ptr,
                reinterpret_cast<const byte*>(key.data())
            ) != 0) {
            std::cerr << "[ERROR] validateAccessTokenBase64: Decryption failed or authentication tag is invalid." << std::endl;
            return std::nullopt;
        }
    
        decrypted_payload_bin.resize(actual_decrypted_payload_len);
    
        // 7. Конвертація розшифрованих байтів у рядок та парсинг JSON
        std::string payload_str(reinterpret_cast<const char*>(decrypted_payload_bin.data()), decrypted_payload_bin.size());
        
        boost::system::error_code ec_json;
        boost::json::value parsed_payload = boost::json::parse(payload_str, ec_json);
    
        if (ec_json) {
            std::cerr << "[ERROR] validateAccessTokenBase64: Failed to parse decrypted payload as JSON: " << ec_json.message() << std::endl;
            return std::nullopt;
        }
    
        if (!parsed_payload.is_object()) {
            std::cerr << "[ERROR] validateAccessTokenBase64: Decrypted payload is not a JSON object." << std::endl;
            return std::nullopt;
        }
    
        return parsed_payload.as_object();
    }
    
}
