#pragma once
#include <string>
#include <string_view>
#include <chrono>
#include <shared_mutex>
#include "keycloak/config/library_config.hpp"

namespace keycloak::pkce {

/**
 * @struct StateEntry
 * @brief Container for PKCE state information
 * 
 * Stores the PKCE code verifier, expiration time, and optional
 * cryptographic hash for enhanced security.
 */
 struct StateEntry {
  std::string code_verifier;                      ///< PKCE code verifier
  std::chrono::system_clock::time_point expiry;   ///< Entry expiration time
  std::string hash;                               ///< Optional crypto hash
};


class IStateStore {
public:
    virtual ~IStateStore() = default;
    virtual std::string create(std::string_view code_verifier) = 0;
    virtual std::string verify(std::string_view state) = 0;
};

/**
 * @class StateStore
 * @brief Thread-safe store for PKCE state management
 * 
 * Features:
 * - Automatic expired state cleanup
 * - Cryptographic verification (optional)
 * - Entry limits with LRU cleanup
 * - Thread-safe operations
 */

class StateStore : public IStateStore {
public:
    /**
     * @brief Creates a new state store
     * @param config State store configuration
     * 
     * Configuration includes:
     * - Expiry duration for states
     * - Maximum number of concurrent states
     * - Cryptographic verification flag
     */
    explicit StateStore(const config::StateStoreConfig& config);

    /**
     * @brief Creates a new state entry
     * @param code_verifier PKCE code verifier to store
     * @return Generated state string
     * @throws std::runtime_error if state generation fails
     * 
     * Process:
     * 1. Cleanup expired entries
     * 2. Check entry limits
     * 3. Generate random state
     * 4. Store state with verifier
     * 5. Add cryptographic binding if enabled
     */
    std::string create(std::string_view code_verifier) override;

    /**
     * @brief Verifies and retrieves code verifier for state
     * @param state State parameter to verify
     * @return Code verifier if valid, empty string if invalid
     * 
     * Validation:
     * 1. State existence
     * 2. Expiration check
     * 3. Cryptographic verification (if enabled)
     * 4. Single-use enforcement (consumed after verification)
     */
    std::string verify(std::string_view state) override;

private:
    /**
     * @brief Creates SHA256 hash of input
     * @param input String to hash
     * @return Hex-encoded hash string
     */
    static std::string create_hash(const std::string& input);

    /**
     * @brief Generates cryptographically secure random state
     * @return 32-character random string
     */
    static std::string generate_random_state();

    /**
     * @brief Removes expired entries from store
     * Thread-safe cleanup of expired states
     */
    void cleanup_expired();

    /**
     * @brief Removes oldest entries when store is full
     * Implements LRU-based cleanup, removing 10% of oldest entries
     */
    void cleanup_oldest();

    std::unordered_map<std::string, StateEntry> store_;   ///< State storage
    mutable std::shared_mutex mutex_;                     ///< Thread safety
    const config::StateStoreConfig& config_;              ///< Configuration
};

} // namespace keycloak::pkce
