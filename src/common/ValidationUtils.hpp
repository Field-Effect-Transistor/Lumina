//  ValidatiomUtils.hpp

#pragma once

#include <string>
#include <regex>
#include <optional>
#include <algorithm>

namespace ValidationUtils {
    struct ValidationError {
        std::string field;
        std::string message;
    };

    const int passwordMinLength = 8;
    const int passwordMaxLength = 128;

    using ValidationResult = std::optional<ValidationError>;

    ValidationResult isValidEmailFormat(const std::string& email);
    ValidationResult isValidPasswordFormat(const std::string& password);
    inline bool isEmpty(const std::string& value) { return value.empty(); }

};
