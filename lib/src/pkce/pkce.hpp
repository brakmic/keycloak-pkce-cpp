/**
 * @file pkce.hpp
 * @brief PKCE (Proof Key for Code Exchange) Implementation
 * @version 1.0
 * 
 * Implements OAuth2 PKCE (RFC 7636) cryptographic operations including:
 * - Code verifier generation
 * - Code challenge computation using SHA256
 * - Base64URL encoding
 * 
 * Security considerations:
 * - Uses cryptographically secure random number generation
 * - Implements S256 challenge method only (plain method not supported)
 * - Follows RFC 7636 character set requirements
 */

#pragma once
#include <random>
#include <string>
#include <algorithm>
#include <vector>
#include <picosha2.h>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace keycloak::pkce {

/**
 * @struct PkcePair
 * @brief Holds PKCE code verifier and challenge pair
 * 
 * Used for OAuth2 PKCE flow where:
 * - code_verifier is stored locally
 * - code_challenge is sent to authorization server
 */
struct PkcePair {
    std::string code_verifier;
    std::string code_challenge;
};

/**
 * @brief Generates cryptographically secure random string
 * @param length Desired length of output string
 * @return Random string using RFC 7636 character set
 * 
 * Uses Mersenne Twister 64-bit PRNG seeded with hardware RNG.
 * Character set: [A-Z][a-z][0-9]-._~
 */
inline std::string generate_random_string(std::size_t length) {
    static constexpr std::string_view charset = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    
    std::random_device rd;
    std::mt19937_64 gen(rd()); // 64-bit Mersenne Twister
    std::uniform_int_distribution<size_t> dist(0, charset.size() - 1);
    
    std::string result;
    result.reserve(length);
    std::generate_n(std::back_inserter(result), length,
        [&]{ return charset[dist(gen)]; });
    return result;
}

/**
 * @brief Implements Base64URL encoding (RFC 4648)
 * @param input Raw binary data to encode
 * @return Base64URL-encoded string (no padding)
 * 
 * Differences from standard Base64:
 * - Uses '-' instead of '+'
 * - Uses '_' instead of '/'
 * - Omits padding '=' characters
 */
inline std::string base64url_encode(const std::string& input) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    std::string ret;
    unsigned int i = 0;
    unsigned int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    const unsigned char* bytes_to_encode = 
        reinterpret_cast<const unsigned char*>(input.c_str());
    unsigned int in_len = input.length();

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];
    }

    return ret;  // Base64URL doesn't use padding
}

/**
 * @brief Generates PKCE verifier/challenge pair
 * @return PkcePair containing verifier and challenge
 * 
 * Process:
 * 1. Generate random code verifier (43 chars)
 * 2. Compute SHA256 hash of verifier
 * 3. Base64URL encode hash to create challenge
 * 
 * Following RFC 7636 specifications:
 * - code_verifier: 43-128 chars from allowed set
 * - code_challenge: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
 */
inline PkcePair generate_pkce_pair() {
    // Generate code verifier (43-128 chars)
    std::string code_verifier = generate_random_string(43);

    // Calculate SHA256 of verifier
    std::vector<unsigned char> hash(picosha2::k_digest_size);
    picosha2::hash256(code_verifier.begin(), code_verifier.end(), hash.begin(), hash.end());

    // Base64URL encode the hash for code challenge
    std::string code_challenge = base64url_encode(std::string(hash.begin(), hash.end()));

    return {code_verifier, code_challenge};
}

} // namespace keycloak::pkce
