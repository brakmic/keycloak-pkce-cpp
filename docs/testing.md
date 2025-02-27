# Testing Guide

## Test Categories

### Unit Tests
Located in `tests/unit/`, these tests verify individual components in isolation:
- `pkce/` - PKCE code generation and state management
- `auth/` - Authentication strategies and token services
- `http/` - HTTP client functionality

### Integration Tests
Located in `tests/integration/`, these tests verify component interactions:
- `auth_flow_test.cpp` - Complete PKCE authentication flow
- `token_exchange_test.cpp` - Token exchange and validation

### End-to-End Tests
Located in `tests/e2e/`, these tests verify the complete system:
- `keycloak_client_test.cpp` - Full authentication flow with Keycloak server

## Building Tests

### Prerequisites
```bash
# Install required packages
sudo apt-get update
sudo apt-get install -y \
    libcurl4-openssl-dev \
    libssl-dev \
    gcovr \
    lcov

# Initialize submodules (if not done)
git submodule update --init --recursive
```

### Basic Build
```bash
# Create build directory
mkdir -p build && cd build

# Configure project with tests
cmake ..

# Build all tests
make unit_tests integration_tests e2e_tests

# Or build specific test suite
make unit_tests        # Only unit tests
make integration_tests # Only integration tests
make e2e_tests        # Only E2E tests
```

### Build with Coverage
```bash
# Configure with coverage enabled
cmake -DENABLE_COVERAGE=ON ..

# Build tests
make coverage
```

## Running Tests

### Individual Test Suites
```bash
# Run unit tests
./tests/unit_tests

# Run integration tests
./tests/integration_tests

# Run E2E tests
./tests/e2e_tests
```

### Using CMake Targets
```bash
# Run specific test suite
make run_unit_tests
make run_integration_tests
make run_e2e_tests

# Run all tests
make run_all_tests
```

### Running Specific Tests
```bash
# Run tests matching a pattern
./tests/unit_tests --gtest_filter=PKCETest.*
./tests/integration_tests --gtest_filter=AuthFlowTest.*
./tests/e2e_tests --gtest_filter=KeycloakClientE2ETest.*
```

### Test Output Options
```bash
# Show all test output
./tests/unit_tests --gtest_output=all

# Generate XML report
./tests/unit_tests --gtest_output=xml:report.xml

# Show test progress
./tests/unit_tests --gtest_print_time=1
```

## Coverage Reports

When built with coverage enabled (`-DENABLE_COVERAGE=ON`):
```bash
# Generate coverage report
make coverage

# View report
xdg-open build/coverage/index.html
```

## Environment Setup for E2E Tests

E2E tests require a running Keycloak instance:
```bash
# Start Keycloak and PostgreSQL
docker-compose up -d

# Wait for Keycloak to be ready
until curl -fs https://keycloak.local.com:9443/health; do
    sleep 5
done

# Now run E2E tests
make run_e2e_tests
```

## Troubleshooting

### Common Issues

1. **Test Discovery Fails**
```bash
# Rebuild test discovery
cmake --build . --target rebuild_cache
```

2. **SSL Certificate Issues**
```bash
# Regenerate certificates
./scripts/certgen/gen_ca_and_certs.sh
```

3. **Integration Tests Fail**
```bash
# Check Keycloak status
docker-compose ps
docker-compose logs keycloak
```

4. **Coverage Report Generation Fails**
```bash
# Install missing tools
sudo apt-get install gcovr lcov
```

### Debug Output
```bash
# Enable verbose test output
GTEST_VERBOSE=1 ./tests/unit_tests

# Enable debug logging
KEYCLOAK_LOG_LEVEL=DEBUG ./tests/integration_tests
```
