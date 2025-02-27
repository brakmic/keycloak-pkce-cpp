#include <gtest/gtest.h>
#include "mocks/pkce/mock_state_store.hpp"

class StateStoreTest : public ::testing::Test {
protected:
    keycloak::config::StateStoreConfig config{
        keycloak::config::Duration(300),  // 5 minutes, using Duration type
        true,   // enable crypto verification
        100     // max entries
    };
    
    keycloak::test::MockStateStore store{config};
};

TEST_F(StateStoreTest, CreateAndVerifyState) {
    const std::string verifier = "test_verifier";
    
    // Create state
    std::string state = store.create_state(verifier);
    EXPECT_FALSE(state.empty());
    
    // Verify and consume
    std::string retrieved = store.verify_and_consume(state);
    EXPECT_EQ(retrieved, verifier);
    
    // Try to verify again (should fail)
    retrieved = store.verify_and_consume(state);
    EXPECT_TRUE(retrieved.empty());
}

TEST_F(StateStoreTest, ExpiredState) {
    const std::string verifier = "test_verifier";
    
    // Create state with very short expiry
    keycloak::config::StateStoreConfig short_config{
        keycloak::config::Duration(1),  // 1 second
        true,
        100
    };
    keycloak::pkce::StateStore short_store{short_config};
    
    std::string state = short_store.create_state(verifier);
    
    // Wait for expiration
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Try to verify expired state
    std::string retrieved = short_store.verify_and_consume(state);
    EXPECT_TRUE(retrieved.empty());
}
