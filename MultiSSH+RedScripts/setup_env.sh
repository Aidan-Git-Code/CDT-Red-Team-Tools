#!/bin/bash
set -e

# ── Config ───────────────────────────────────────────────
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_DIR}/.venv"
ALIAS_NAME="multissh-activate"

echo "========================================"
echo "  MultiSSH Environment Setup"
echo "========================================"
echo "Project dir: ${PROJECT_DIR}"
echo ""

# ── 1. System dependencies ──────────────────────────────
echo "[1/6] Installing system dependencies..."
sudo apt update -qq
sudo apt install -y -qq python3 python3-venv python3-pip > /dev/null 2>&1
echo "  ✅ python3, python3-venv, python3-pip installed"

# ── 2. Clean old / misplaced venvs ──────────────────────
echo "[2/6] Cleaning up old environments..."
# Remove venv if it exists inside the package dir (wrong location)
if [ -d "${PROJECT_DIR}/multissh/.venv" ]; then
    rm -rf "${PROJECT_DIR}/multissh/.venv"
    echo "  🗑️  Removed misplaced venv from multissh/.venv"
fi
# Remove old venv at correct location to start fresh
if [ -d "${VENV_DIR}" ]; then
    rm -rf "${VENV_DIR}"
    echo "  🗑️  Removed old venv"
fi

# ── 3. Create venv ──────────────────────────────────────
echo "[3/6] Creating virtual environment at .venv/..."
python3 -m venv "${VENV_DIR}"
echo "  ✅ venv created"

# ── 4. Install dependencies ─────────────────────────────
echo "[4/6] Installing Python dependencies..."
source "${VENV_DIR}/bin/activate"
pip install --upgrade pip --quiet
pip install -r "${PROJECT_DIR}/requirements.txt" --quiet
echo "  ✅ Dependencies installed"

# ── 5. Install the multissh package ─────────────────────
echo "[5/6] Installing multissh in editable mode..."
pip install -e "${PROJECT_DIR}" --quiet
echo "  ✅ multissh installed"

# Verify
if ! command -v multissh &> /dev/null; then
    echo "  ❌ ERROR: multissh command not found after install"
    echo "     Check setup.py entry_points"
    exit 1
fi
echo "  ✅ 'multissh' command available at: $(which multissh)"

# ── 6. Shell alias ──────────────────────────────────────
echo "[6/6] Configuring shell alias..."

ALIAS_LINE="alias ${ALIAS_NAME}=\"source ${VENV_DIR}/bin/activate\""

# Add to .bashrc if not already present
if ! grep -qF "${ALIAS_NAME}" ~/.bashrc 2>/dev/null; then
    echo "" >> ~/.bashrc
    echo "# MultiSSH virtual environment" >> ~/.bashrc
    echo "${ALIAS_LINE}" >> ~/.bashrc
    echo "  ✅ Added alias '${ALIAS_NAME}' to ~/.bashrc"
else
    # Update existing alias in case path changed
    sed -i "s|^alias ${ALIAS_NAME}=.*|${ALIAS_LINE}|" ~/.bashrc
    echo "  ✅ Updated alias '${ALIAS_NAME}' in ~/.bashrc"
fi

# Also add to .zshrc if zsh is used
if [ -f ~/.zshrc ]; then
    if ! grep -qF "${ALIAS_NAME}" ~/.zshrc 2>/dev/null; then
        echo "" >> ~/.zshrc
        echo "# MultiSSH virtual environment" >> ~/.zshrc
        echo "${ALIAS_LINE}" >> ~/.zshrc
        echo "  ✅ Added alias to ~/.zshrc"
    fi
fi

# Activate
multissh-activate

# ── Done ────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  ✅ Setup complete!"
echo "========================================"
echo ""
echo "Usage:"
echo "  source ${VENV_DIR}/bin/activate    # activate now"
echo "  ${ALIAS_NAME}                           # or use alias (new shells)"
echo ""
echo "  multissh -c passwordAuth.yaml run \"whoami\""
echo "  multissh -c passwordAuth.yaml run --sudo \"apt update\""
echo "  multissh -c passwordAuth.yaml interactive"
echo "  multissh -c passwordAuth.yaml check"
echo ""
echo "Venv is currently ACTIVE. You're ready to go."
echo "========================================"
