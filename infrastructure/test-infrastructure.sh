#!/bin/bash

# Test script for VirusJaeger multi-engine infrastructure
# This script validates the infrastructure setup and API functionality

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_BASE="http://localhost:8000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

# Function to wait for API to be ready
wait_for_api() {
    info "Waiting for API to be ready..."
    for i in {1..30}; do
        if curl -s "${API_BASE}/health" > /dev/null 2>&1; then
            success "API is ready"
            return 0
        fi
        echo -n "."
        sleep 2
    done
    error "API failed to start within 60 seconds"
    return 1
}

# Test API health endpoint
test_health() {
    info "Testing health endpoint..."
    response=$(curl -s "${API_BASE}/health" || echo "FAILED")
    if [[ "$response" == "FAILED" ]]; then
        error "Health endpoint failed"
        return 1
    fi
    
    echo "$response" | grep -q "\"status\":\"ok\"" && success "Health endpoint working" || warning "Health endpoint response unexpected"
    
    # Check if engines are reported
    if echo "$response" | grep -q "engines"; then
        success "Engine health monitoring active"
    else
        warning "Engine health monitoring not available (Celery may not be running)"
    fi
}

# Test file upload endpoint
test_file_upload() {
    info "Testing file upload endpoint..."
    
    # Create test file (EICAR test string)
    echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
    
    # Test normal upload
    response=$(curl -s -X POST "${API_BASE}/files" -F "file=@/tmp/eicar.txt" || echo "FAILED")
    if [[ "$response" == "FAILED" ]]; then
        error "File upload failed"
        return 1
    fi
    
    sha256=$(echo "$response" | grep -o '"sha256":"[^"]*"' | cut -d'"' -f4)
    if [[ -n "$sha256" ]]; then
        success "File upload successful (SHA256: $sha256)"
    else
        error "File upload response missing SHA256"
        return 1
    fi
    
    # Test multi-engine upload with query parameter
    response=$(curl -s -X POST "${API_BASE}/files?multi_engine=true" -F "file=@/tmp/eicar.txt" || echo "FAILED")
    if echo "$response" | grep -q "multi-engine"; then
        success "Multi-engine query parameter working"
    else
        warning "Multi-engine query parameter not working as expected"
    fi
    
    rm -f /tmp/eicar.txt
}

# Test API info endpoint
test_api_info() {
    info "Testing API info endpoint..."
    response=$(curl -s "${API_BASE}/api-info" || echo "FAILED")
    if [[ "$response" == "FAILED" ]]; then
        warning "API info endpoint not available"
    else
        success "API info endpoint working"
    fi
}

# Test with demo API key
test_authenticated_endpoints() {
    info "Testing authenticated endpoints with demo API key..."
    
    # Create test file
    echo 'Test malware sample' > /tmp/test.bin
    
    # Test multi-engine endpoint
    response=$(curl -s -X POST "${API_BASE}/files/multi-engine" \
        -H "Authorization: Bearer demo-api-key" \
        -F "file=@/tmp/test.bin" || echo "FAILED")
    
    if [[ "$response" == "FAILED" ]]; then
        warning "Multi-engine endpoint failed (may require running workers)"
    elif echo "$response" | grep -q "multi-engine"; then
        success "Multi-engine endpoint working"
    else
        warning "Multi-engine endpoint response unexpected"
    fi
    
    rm -f /tmp/test.bin
}

# Check Docker Compose services
check_docker_services() {
    info "Checking Docker Compose services..."
    
    if ! command -v docker &> /dev/null; then
        warning "Docker not available - skipping service checks"
        return 0
    fi
    
    cd "$SCRIPT_DIR"
    
    # Check if compose file exists
    if [[ ! -f "docker-compose.yml" ]]; then
        error "docker-compose.yml not found in infrastructure directory"
        return 1
    fi
    
    # Validate compose file
    if docker compose config > /dev/null 2>&1; then
        success "Docker Compose configuration is valid"
    else
        error "Docker Compose configuration is invalid"
        return 1
    fi
    
    # Check if services are defined
    services=$(docker compose config --services 2>/dev/null || echo "")
    expected_services="api worker-scan worker-clamav worker-yara worker-orchestrator"
    
    for service in $expected_services; do
        if echo "$services" | grep -q "^${service}$"; then
            success "Service '$service' defined"
        else
            error "Service '$service' missing from configuration"
        fi
    done
}

# Main test execution
main() {
    echo "VirusJaeger Infrastructure Test Suite"
    echo "====================================="
    echo ""
    
    # Check infrastructure configuration
    check_docker_services
    echo ""
    
    # If API is running, test it
    if curl -s "${API_BASE}/health" > /dev/null 2>&1; then
        info "API is running, performing live tests..."
        test_health
        test_file_upload
        test_api_info
        test_authenticated_endpoints
    else
        warning "API not running on ${API_BASE} - skipping live tests"
        info "To run live tests:"
        info "1. cd infrastructure"
        info "2. docker compose up -d"
        info "3. ./test-infrastructure.sh"
    fi
    
    echo ""
    success "Infrastructure test suite completed"
    echo ""
    info "Next steps:"
    info "- Start services: cd infrastructure && docker compose up -d"
    info "- View logs: docker compose logs -f"
    info "- Access API docs: http://localhost:8000/docs"
    info "- Access frontend: http://localhost:3000"
}

main "$@"