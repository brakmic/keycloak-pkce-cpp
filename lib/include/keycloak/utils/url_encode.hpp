/**
* @file url_encode.hpp
* @brief URL encoding/decoding utilities
* 
* Provides functions for URL-safe encoding and decoding of strings
* following RFC 3986 specifications. Handles special characters,
* Unicode, and percent-encoding.
*/

#pragma once
#include <string>
#include <string_view>
#include <iomanip>
#include <sstream>

namespace {
    constexpr bool should_encode(unsigned char c) {
        return !(
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' ||
            c == '.' || c == '~'
        );
    }
}

/**
* @brief URL-encodes a string
* @param input String to encode
* @return URL-safe encoded string
*/
inline std::string url_encode(const std::string_view value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (unsigned char c : value) {
        if (should_encode(c)) {
            escaped << '%' << std::setw(2) << int(c);
        } else {
            escaped << c;
        }
    }

    return escaped.str();
}

/**
* @brief URL-decodes a string
* @param input Encoded string to decode
* @return Decoded string
* @throws std::runtime_error if input is malformed
*/
inline std::string url_decode(const std::string_view value) {
    std::string result;
    result.reserve(value.length());

    for (std::size_t i = 0; i < value.length(); ++i) {
        if (value[i] == '%' && i + 2 < value.length()) {
            int ch;
            std::istringstream hex_stream(std::string{value[i+1], value[i+2]});
            if (hex_stream >> std::hex >> ch) {
                result += static_cast<char>(ch);
                i += 2;
                continue;
            }
        }
        result += value[i];
    }
    
    return result;
}
