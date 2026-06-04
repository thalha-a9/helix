#!/usr/bin/env bash
# Helix — One-Click Installer
# curl -sSL https://raw.githubusercontent.com/thalha-a9/helix/main/install.sh | bash

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[!]${NC} $1"; exit 1; }

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Helix — Installer              ║${NC}"
echo -e "${CYAN}║   github.com/thalha-a9/helix     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# Python check
if command -v python3 &>/dev/null; then
    ok "Python3: $(python3 --version)"
else
    info "Installing Python3..."
    sudo apt-get update -qq && sudo apt-get install -y python3 python3-pip || err "Python3 install failed"
fi

# pip check
if ! command -v pip3 &>/dev/null; then
    info "Installing pip3..."
    sudo apt-get install -y python3-pip -qq
fi

# git check
if command -v git &>/dev/null; then
    ok "Git: $(git --version)"
else
    info "Installing git..."
    sudo apt-get install -y git -qq
fi

# Clone
REPO_DIR="helix"
if [ -d "$REPO_DIR" ]; then
    warn "Directory exists — pulling latest..."
    cd "$REPO_DIR" && git pull && cd ..
else
    info "Cloning helix..."
    git clone https://github.com/thalha-a9/helix.git
fi
ok "Repo ready at ./$REPO_DIR"

# Python deps
info "Installing Python dependencies..."
cd "$REPO_DIR"
pip3 install -r requirements.txt --quiet 2>/dev/null || \
pip3 install -r requirements.txt --break-system-packages --quiet
ok "Dependencies installed"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Done! Run Helix:               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}cd helix${NC}"
echo -e "  ${CYAN}python3 helix.py -u <username>${NC}"
echo ""
echo -e "  Examples:"
echo -e "  ${YELLOW}python3 helix.py -u johndoe${NC}"
echo -e "  ${YELLOW}python3 helix.py -u johndoe --format all${NC}"
echo -e "  ${YELLOW}python3 helix.py -u johndoe --no-browser${NC}"
echo ""
