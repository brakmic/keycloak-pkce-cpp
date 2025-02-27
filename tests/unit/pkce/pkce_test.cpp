#include <gtest/gtest.h>
#include "pkce/pkce.hpp"
#include <regex>

TEST(PKCETest, GenerateRandomString) {
    using namespace keycloak::pkce;
    
    auto str = generate_random_string(43);
    EXPECT_EQ(str.length(), 43);
    
    // Check characters are from allowed set
    const std::string allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    for (char c : str) {
        EXPECT_NE(allowed.find(c), std::string::npos);
    }
}

TEST(PKCETest, GeneratePKCEPair) {
    using namespace keycloak::pkce;
    
    auto pair = generate_pkce_pair();
    
    // Verify verifier length
    EXPECT_EQ(pair.code_verifier.length(), 43);
    
    // Verify challenge is Base64URL encoded using proper regex
    std::regex base64url_regex("^[A-Za-z0-9_-]+$");
    EXPECT_TRUE(std::regex_match(pair.code_challenge, base64url_regex));
}
