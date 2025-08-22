#!/bin/bash

# VirusJaeger Infrastructure Setup Script
# Helps with common infrastructure management tasks

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    echo "VirusJaeger Infrastructure Management"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start           Start all services"
    echo "  stop            Stop all services"
    echo "  restart         Restart all services"
    echo "  build           Build all images"
    echo "  status          Show service status"
    echo "  logs [service]  Show logs (optional service name)"
    echo "  scale           Scale worker services"
    echo "  health          Check service health"
    echo "  clean           Clean up containers and volumes"
    echo "  setup-rules     Install sample Yara rules"
    echo "  update-clamav   Update ClamAV signatures"
    echo ""
}

start_services() {
    info "Starting VirusJaeger infrastructure..."
    docker compose up -d
    success "All services started"
    info "API: http://localhost:8000/docs"
    info "Frontend: http://localhost:3000"
    info "RabbitMQ: http://localhost:15672 (guest/guest)"
    info "MinIO: http://localhost:9001 (minioadmin/minioadmin)"
}

stop_services() {
    info "Stopping VirusJaeger infrastructure..."
    docker compose down
    success "All services stopped"
}

restart_services() {
    stop_services
    start_services
}

build_images() {
    info "Building all Docker images..."
    docker compose build --no-cache
    success "All images built"
}

show_status() {
    info "Service status:"
    docker compose ps
}

show_logs() {
    if [ -n "$1" ]; then
        info "Showing logs for service: $1"
        docker compose logs -f "$1"
    else
        info "Showing logs for all services:"
        docker compose logs -f
    fi
}

scale_workers() {
    info "Current worker scaling options:"
    echo "1. Scale ClamAV workers"
    echo "2. Scale Yara workers"
    echo "3. Scale scan workers"
    echo "4. Custom scaling"
    echo ""
    read -p "Select option (1-4): " choice
    
    case $choice in
        1)
            read -p "Number of ClamAV workers: " count
            docker compose up -d --scale worker-clamav="$count"
            ;;
        2)
            read -p "Number of Yara workers: " count
            docker compose up -d --scale worker-yara="$count"
            ;;
        3)
            read -p "Number of scan workers: " count
            docker compose up -d --scale worker-scan="$count"
            ;;
        4)
            read -p "Service name: " service
            read -p "Number of instances: " count
            docker compose up -d --scale "$service=$count"
            ;;
        *)
            error "Invalid option"
            exit 1
            ;;
    esac
    success "Scaling completed"
}

check_health() {
    info "Checking service health..."
    
    # Check API health
    if curl -s http://localhost:8000/health > /dev/null; then
        success "API is healthy"
    else
        error "API is not responding"
    fi
    
    # Check RabbitMQ
    if curl -s http://localhost:15672 > /dev/null; then
        success "RabbitMQ is healthy"
    else
        error "RabbitMQ is not responding"
    fi
    
    # Check database
    if docker compose exec -T postgres pg_isready -U virus > /dev/null 2>&1; then
        success "PostgreSQL is healthy"
    else
        error "PostgreSQL is not responding"
    fi
    
    # Check worker queues
    info "Worker queue status:"
    docker compose exec -T rabbitmq rabbitmqctl list_queues 2>/dev/null || warning "Could not check queue status"
}

clean_up() {
    warning "This will remove all containers, images, and volumes!"
    read -p "Are you sure? (y/N): " confirm
    if [[ $confirm == [yY] ]]; then
        info "Cleaning up..."
        docker compose down -v --rmi all
        success "Cleanup completed"
    else
        info "Cleanup cancelled"
    fi
}

setup_yara_rules() {
    info "Setting up Yara rules..."
    
    # Create volume if it doesn't exist
    docker volume create virusjaeger_yara_rules 2>/dev/null || true
    
    # Copy default rules
    docker run --rm -v "$(pwd)/yara-rules:/source" -v virusjaeger_yara_rules:/dest alpine:latest cp -r /source/* /dest/
    
    success "Yara rules installed"
    info "You can add custom rules to the yara_rules volume"
}

update_clamav() {
    info "Updating ClamAV signatures..."
    docker compose exec worker-clamav freshclam --no-warnings
    success "ClamAV signatures updated"
}

# Main command handling
case "${1:-}" in
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    build)
        build_images
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "$2"
        ;;
    scale)
        scale_workers
        ;;
    health)
        check_health
        ;;
    clean)
        clean_up
        ;;
    setup-rules)
        setup_yara_rules
        ;;
    update-clamav)
        update_clamav
        ;;
    help|--help|-h)
        usage
        ;;
    "")
        usage
        ;;
    *)
        error "Unknown command: $1"
        usage
        exit 1
        ;;
esac