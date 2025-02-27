#pragma once
#include "keycloak/pkce/state_store.hpp"

namespace keycloak::test {

class MockStateStore : public pkce::IStateStore {
public:
    explicit MockStateStore(const config::StateStoreConfig& config) 
        : config_(config) {}

    std::string create(std::string_view code_verifier) override {
        if (code_verifier.empty()) {
            return "";
        }
        last_verifier_ = std::string(code_verifier);
        return "mock_state_" + last_verifier_;
    }

    std::string verify(std::string_view state) override {
        if (state.empty() || last_verifier_.empty()) {
            return "";
        }
        
        std::string state_str{state};
        if (state_str == "mock_state_" + last_verifier_) {
            auto verifier = last_verifier_;
            last_verifier_.clear();  // Consume the state
            return verifier;
        }
        return "";
    }

private:
    const config::StateStoreConfig& config_;
    std::string last_verifier_;
};

} // namespace keycloak::test
