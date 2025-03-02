/**
 * @file state_store.hpp
 * @brief Thread-safe PKCE State Management
 * @version 1.0
 * 
 * Implements secure storage and validation of PKCE state parameters.
 * Provides automatic cleanup, cryptographic verification, and
 * thread-safe access to state information.
 */
#include <algorithm>
#include <string>
#include <string_view>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <chrono>
#include <ranges>
#include "pkce.hpp"
#include "picosha2.h"
#include "keycloak/config/library_config.hpp"
#include "keycloak/pkce/state_store.hpp"
#include "keycloak/utils/logging.hpp"

namespace keycloak::pkce {
    
StateStore::StateStore(const config::StateStoreConfig& config)
    : config_(config)
{
    logging::Logger::debug("StateStore initialized with:");
    logging::Logger::debug("  Expiry duration: {}s", config.expiry_duration.count());
    logging::Logger::debug("  Max entries: {}", config.max_entries);
    logging::Logger::debug("  Cryptographic verification: {}", 
        config.enable_cryptographic_verification ? "enabled" : "disabled");
}

std::string StateStore::create(std::string_view code_verifier) {
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

std::string StateStore::verify(std::string_view state) {
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

std::string StateStore::create_hash(const std::string& input) {
    return picosha2::hash256_hex_string(input);
}

std::string StateStore::generate_random_state() {
    return generate_random_string(32);
}

void StateStore::cleanup_expired() {
    std::unique_lock lock(mutex_);
    auto now = std::chrono::system_clock::now();
    
    std::erase_if(store_, [now](const auto& pair) {
        return pair.second.expiry < now;
    });
}

void StateStore::cleanup_oldest() {
    std::unique_lock lock(mutex_);
    if (store_.empty()) return;

    size_t to_remove = std::max<size_t>(1, store_.size() / 10);

    auto entries = store_ 
        | std::views::transform([](const auto& pair) {
            return std::pair{pair.first, pair.second.expiry};
        })
        | std::ranges::to<std::vector>();

    std::ranges::sort(entries, {}, &std::pair<std::string,
        std::chrono::system_clock::time_point>::second);

    std::ranges::for_each(
        entries | std::views::take(to_remove),
        [this](const auto& pair) { store_.erase(pair.first); }
    );
}

} // namespace keycloak::pkce
