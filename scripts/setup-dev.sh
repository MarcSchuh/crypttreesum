#!/usr/bin/env bash

# crypttreesum Development Environment Setup Script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_uv() {
    if ! command_exists uv; then
        log_error "uv is not installed on your system."
        echo
        echo "To install uv, run:"
        echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
        exit 1
    fi
    log_success "uv is installed"
}

setup_python_env() {
    log_info "Setting up Python environment..."
    cd "$PROJECT_ROOT"

    if [[ ! -d ".venv" ]]; then
        log_info "Creating virtual environment..."
        uv venv
    else
        log_info "Virtual environment already exists"
    fi

    # shellcheck disable=SC1091
    source .venv/bin/activate
    log_success "Python environment setup complete"
}

install_python_dependencies() {
    log_info "Installing Python dependencies..."
    cd "$PROJECT_ROOT"
    # shellcheck disable=SC1091
    source .venv/bin/activate

    if ! uv sync --all-extras; then
        log_error "Failed to install dependencies"
        exit 1
    fi
    log_success "Python dependencies installed"
}

setup_pre_commit() {
    log_info "Setting up pre-commit hooks..."
    cd "$PROJECT_ROOT"
    # shellcheck disable=SC1091
    source .venv/bin/activate

    if ! command_exists pre-commit; then
        log_error "pre-commit not found in virtual environment"
        return 1
    fi

    if ! pre-commit install; then
        log_error "Failed to install pre-commit hooks"
        return 1
    fi

    if ! pre-commit install --hook-type commit-msg; then
        log_warning "Failed to install commit-msg hook"
    fi

    log_success "Pre-commit hooks installed"
}

show_summary() {
    log_success "crypttreesum development environment setup complete!"
    echo
    echo "Next steps:"
    echo "  1. Activate the virtual environment: source .venv/bin/activate"
    echo "  2. Run tests: uv run pytest"
    echo "  3. Run linting: uv run ruff check --fix src/ tests/"
    echo "  4. Start developing!"
}

main() {
    echo "=============================================="
    echo "  crypttreesum Development Environment Setup"
    echo "=============================================="
    echo

    check_uv
    setup_python_env
    install_python_dependencies
    setup_pre_commit
    show_summary
}

main "$@"
