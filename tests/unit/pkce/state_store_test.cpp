#include <gtest/gtest.h>
#include "mocks/pkce/mock_state_store.hpp"

class StateStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        config = keycloak::config::StateStoreConfig{
            keycloak::config::Duration(300),  // 5 minutes
            true,   // enable crypto verification
            100     // max entries
        };
        store = std::make_unique<keycloak::test::MockStateStore>(config);
    }

    keycloak::config::StateStoreConfig config;
    std::unique_ptr<keycloak::pkce::IStateStore> store;
};

TEST_F(StateStoreTest, CreateAndVerifyState) {
    const std::string verifier = "test_verifier";
    
    // Create state
    std::string state = store->create(verifier);
    EXPECT_FALSE(state.empty());
    EXPECT_EQ(state, "mock_state_" + verifier);
    
    // Verify and consume
    std::string retrieved = store->verify(state);
    EXPECT_EQ(retrieved, verifier);
    
    // Try to verify again (should fail)
    retrieved = store->verify(state);
    EXPECT_TRUE(retrieved.empty());
}

TEST_F(StateStoreTest, InvalidVerifier) {
    // Try with empty verifier
    std::string state = store->create("");
    EXPECT_TRUE(state.empty());
}

TEST_F(StateStoreTest, InvalidState) {
    // Try to verify invalid state
    std::string retrieved = store->verify("invalid_state");
    EXPECT_TRUE(retrieved.empty());
}
