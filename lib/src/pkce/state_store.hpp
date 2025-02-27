/**
 * @file state_store.hpp
 * @brief Thread-safe PKCE State Management
 * @version 1.0
 * 
 * Implements secure storage and validation of PKCE state parameters.
 * Provides automatic cleanup, cryptographic verification, and
 * thread-safe access to state information.
 */

#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <chrono>
#include "pkce.hpp"
#include "picosha2.h"
#include "keycloak/utils/logging.hpp"
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
class StateStore {
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
    explicit StateStore(const config::StateStoreConfig& config)
        : config_(config)
    {
        logging::Logger::debug("StateStore initialized with:");
        logging::Logger::debug("  Expiry duration: {}s", config.expiry_duration.count());
        logging::Logger::debug("  Max entries: {}", config.max_entries);
        logging::Logger::debug("  Cryptographic verification: {}", 
            config.enable_cryptographic_verification ? "enabled" : "disabled");
    }

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
    std::string create_state(std::string_view code_verifier) {
        cleanup_expired();
        
        if (store_.size() >= config_.max_entries) {
            logging::Logger::warn("StateStore: Max entries reached, clearing oldest entries");
            cleanup_oldest();
        }

        auto state = generate_random_state();
        auto now = std::chrono::system_clock::now();
        auto entry = StateEntry{
            std::string(code_verifier),
            now + config_.expiry_duration.to_duration(),
            config_.enable_cryptographic_verification ? 
                create_hash(state + std::string(code_verifier)) : 
                std::string{}
        };

        std::unique_lock lock(mutex_);
        store_.emplace(state, std::move(entry));
        return state;
    }

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
    std::string verify_and_consume(std::string_view state) {
        cleanup_expired();
        
        std::unique_lock lock(mutex_);
        auto it = store_.find(std::string(state));
        
        if (it == store_.end()) {
            logging::Logger::debug("State not found: {}", state);
            return {};
        }

        auto& entry = it->second;
        
        if (std::chrono::system_clock::now() > entry.expiry) {
            logging::Logger::warn("State expired: {}", state);
            store_.erase(it);
            return {};
        }

        if (config_.enable_cryptographic_verification) {
            std::string current_hash = create_hash(std::string(state) + entry.code_verifier);
            if (current_hash != entry.hash) {
                logging::Logger::error("State verification failed: hash mismatch");
                store_.erase(it);
                return {};
            }
        }

        auto verifier = std::move(entry.code_verifier);
        store_.erase(it);
        return verifier;
    }

private:
    std::unordered_map<std::string, StateEntry> store_;  ///< State storage
    mutable std::shared_mutex mutex_;                     ///< Thread safety
    const config::StateStoreConfig& config_;              ///< Configuration

    /**
     * @brief Creates SHA256 hash of input
     * @param input String to hash
     * @return Hex-encoded hash string
     */
    static std::string create_hash(const std::string& input) {
        return picosha2::hash256_hex_string(input);
    }

    /**
     * @brief Generates cryptographically secure random state
     * @return 32-character random string
     */
    static std::string generate_random_state() {
        return generate_random_string(32);
    }

    /**
     * @brief Removes expired entries from store
     * Thread-safe cleanup of expired states
     */
    void cleanup_expired() {
        std::unique_lock lock(mutex_);
        auto now = std::chrono::system_clock::now();
        
        for (auto it = store_.begin(); it != store_.end();) {
            if (it->second.expiry < now) {
                it = store_.erase(it);
            } else {
                ++it;
            }
        }
    }

    /**
     * @brief Removes oldest entries when store is full
     * Implements LRU-based cleanup, removing 10% of oldest entries
     */
    void cleanup_oldest() {
        std::unique_lock lock(mutex_);
        if (store_.empty()) return;

        size_t to_remove = store_.size() / 10;  // Remove 10% of entries
        if (to_remove == 0) to_remove = 1;

        std::vector<std::pair<std::string, std::chrono::system_clock::time_point>> entries;
        entries.reserve(store_.size());
        
        for (const auto& [state, entry] : store_) {
            entries.emplace_back(state, entry.expiry);
        }

        std::sort(entries.begin(), entries.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });

        for (size_t i = 0; i < to_remove && i < entries.size(); ++i) {
            store_.erase(entries[i].first);
        }
    }
};

} // namespace keycloak::pkce
