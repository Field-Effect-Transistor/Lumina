//  ValidationUtils.cpp

#include "ValidationUtils.hpp"

namespace ValidationUtils {

    ValidationResult validateEmail(const std::string& email) {
        if (isEmpty(email)) {
            return ValidationError{"email", "Email cannot be empty."};
        }

        if (email.length() > 254) {
            return ValidationError{"email", "Email is too long (maximum 254 characters)."};
        }

        size_t atPos = email.find('@');
        if (atPos == std::string::npos) {
            return ValidationError{"email", "Email must contain an '@' symbol."};
        }
        if (atPos == 0) {
            return ValidationError{"email", "The local part of the email (before '@') cannot be empty."};
        }
        if (atPos == email.length() - 1) {
            return ValidationError{"email", "The domain part of the email (after '@') cannot be empty."};
        }

        std::string localPart = email.substr(0, atPos);
        std::string domainPart = email.substr(atPos + 1);

        if (localPart.length() > 64) {
             return ValidationError{"email", "The local part of the email is too long (maximum 64 characters)."};
        }

        if (domainPart.empty()) {
            return ValidationError{"email", "The domain part of the email cannot be empty."};
        }
        if (domainPart.length() > 253) {
             return ValidationError{"email", "The domain part of the email is too long."};
        }

        size_t dotPos = domainPart.find('.');
        if (dotPos == std::string::npos) {
            return ValidationError{"email", "The domain part of the email must contain a '.' symbol."};
        }
        if (dotPos == 0 || dotPos == domainPart.length() - 1) {
            return ValidationError{"email", "The '.' symbol in the domain part is misplaced."};
        }
        
        size_t lastDotPos = domainPart.rfind('.');
        if (lastDotPos != std::string::npos && domainPart.length() - lastDotPos -1 < 2) {
            return ValidationError{"email", "The top-level domain (after the last dot) is too short."};
        }

        const std::regex emailRegex(
            R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)"
        );
        if (!std::regex_match(email, emailRegex)) {
             return ValidationError{"email", "Email format is invalid according to general pattern."};
        }
        
        if (domainPart.find("..") != std::string::npos) {
            return ValidationError{"email", "The domain part of the email contains consecutive dots."};
        }

        if (!localPart.empty() && (localPart.front() == '-' || localPart.back() == '-')) {
            return ValidationError{"email", "The local part of the email must not start or end with a hyphen."};
        }
        if (!domainPart.empty()) {
            std::string domain_segment_check = domainPart;
            size_t current_pos = 0;
            while((current_pos = domain_segment_check.find('.')) != std::string::npos) {
                std::string segment = domain_segment_check.substr(0, current_pos);
                if (!segment.empty() && (segment.front() == '-' || segment.back() == '-')) {
                     return ValidationError{"email", "A domain segment must not start or end with a hyphen."};
                }
                domain_segment_check.erase(0, current_pos + 1);
            }
            if (!domain_segment_check.empty() && (domain_segment_check.front() == '-' || domain_segment_check.back() == '-')) {
                 return ValidationError{"email", "A domain segment must not start or end with a hyphen."};
            }
        }

        return std::nullopt; 
    }

    ValidationResult validatePassword(const std::string& password) {
        if (isEmpty(password)) {
            return ValidationError{"password", "Password cannot be empty."};
        }

        if (password.length() < passwordMinLength) {
            return ValidationError{"password", "Password is too short (minimum " + std::to_string(passwordMinLength) + " characters)."};
        }

        if (password.length() > passwordMaxLength) {
            return ValidationError{"password", "Password is too long (maximum " + std::to_string(passwordMaxLength) + " characters)."};
        }

        bool hasUpperCase = false;
        bool hasLowerCase = false;
        bool hasDigit = false;
        bool hasSpecialChar = false;

        for (char c : password) {
            if (std::isupper(static_cast<unsigned char>(c))) {
                hasUpperCase = true;
            } else if (std::islower(static_cast<unsigned char>(c))) {
                hasLowerCase = true;
            } else if (std::isdigit(static_cast<unsigned char>(c))) {
                hasDigit = true;
            } else if (std::string("!@#$%^&*()_+-=[]{};':\",./<>?").find(c) != std::string::npos) {
                 hasSpecialChar = true;
            }
        }

        if (!hasUpperCase) {
            return ValidationError{"password", "Password must contain at least one uppercase letter."};
        }

        if (!hasLowerCase) {
            return ValidationError{"password", "Password must contain at least one lowercase letter."};
        }

        if (!hasDigit) {
            return ValidationError{"password", "Password must contain at least one digit."};
        }

        if (!hasSpecialChar) {
             return ValidationError{"password", "Password must contain at least one special character."};
        }

        return std::nullopt;
    }
}
