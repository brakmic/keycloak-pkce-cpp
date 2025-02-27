#pragma once
#include "keycloak/config/library_config.hpp"
#include "pkce/state_store.hpp"

namespace keycloak::test {

class MockStateStore {
public:
    explicit MockStateStore(const config::StateStoreConfig& config) 
        : config_(config) {}

    std::string create_state(const std::string& code_verifier) {
        if (code_verifier.empty()) {
            return "";
        }
        last_verifier_ = code_verifier;
        return "mock_state_" + code_verifier;
    }

    std::string verify_and_consume(std::string_view state) {
        if (state.empty() || last_verifier_.empty()) {
            return "";
        }
        
        // Check if this is our mock state
        std::string state_str{state};
        if (state_str == "mock_state_" + last_verifier_) {
            auto verifier = last_verifier_;
            last_verifier_.clear();  // Consume the state
            return verifier;
        }
        return "";
    }

    void cleanup_expired() {
        // No-op in mock
    }

private:
    const config::StateStoreConfig& config_;
    std::string last_verifier_;
};

} // namespace keycloak::test
