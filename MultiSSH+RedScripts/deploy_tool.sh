#!/bin/bash
set -e

# ── Usage ────────────────────────────────────────────────
# ./deploy_tool.sh <config.yaml> <local_tool_directory> [remote_install_command]
#
# Examples:
#   ./deploy_tool.sh passwordAuth.yaml /home/cyberrange/mytool "make install"
#   ./deploy_tool.sh passwordAuth.yaml /home/cyberrange/myapp "pip3 install ."
#   ./deploy_tool.sh passwordAuth.yaml /home/cyberrange/scripts ""
#   ./deploy_tool.sh passwordAuth.yaml /home/cyberrange/myapp "./install.sh"

CONFIG="${1:?Usage: $0 <config.yaml> <local_dir> [install_command]}"
LOCAL_DIR="${2:?Usage: $0 <config.yaml> <local_dir> [install_command]}"
INSTALL_CMD="${3:-}"

TOOL_NAME="$(basename "${LOCAL_DIR}")"
ARCHIVE="/tmp/${TOOL_NAME}.tar.gz"
REMOTE_ARCHIVE="/tmp/${TOOL_NAME}.tar.gz"
REMOTE_DIR="/opt/${TOOL_NAME}"

echo "========================================"
echo "  Deploy: ${TOOL_NAME}"
echo "  To hosts in: ${CONFIG}"
echo "========================================"

# ── Activate venv ────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/.venv/bin/activate"

# ── 1. Create archive ───────────────────────────────────
echo "[1/4] Packaging ${LOCAL_DIR}..."
tar czf "${ARCHIVE}" -C "$(dirname "${LOCAL_DIR}")" "${TOOL_NAME}"
SIZE=$(du -h "${ARCHIVE}" | cut -f1)
echo "  ✅ Created ${ARCHIVE} (${SIZE})"

# ── 2. Upload to all hosts ──────────────────────────────
echo "[2/4] Uploading to all hosts..."
multissh -c "${CONFIG}" upload "${ARCHIVE}" "${REMOTE_ARCHIVE}"
echo "  ✅ Upload complete"

sleep 1

# ── 3. Extract on all hosts ─────────────────────────────
echo "[3/4] Extracting on all hosts..."
multissh -c "${CONFIG}" run "sudo mkdir -p ${REMOTE_DIR}"
echo "[3.3/4] splitting up the commadns to debug :)"
multissh -c "${CONFIG}" run "sudo tar xzf ${REMOTE_ARCHIVE} -C ${REMOTE_DIR}" 
echo "[3.7/4] splitting up the commadns to debug :)"
multissh -c "${CONFIG}" run "sudo rm -f ${REMOTE_ARCHIVE}"
echo "  ✅ Extracted to ${REMOTE_DIR}"

sleep 1
# ── 4. Run install command ──────────────────────────────
if [ -n "${INSTALL_CMD}" ]; then
    echo "[4/4] Running install command: ${INSTALL_CMD}"
    # if ["${INSTALL_CMD}" == ] ; then
    #     multissh -c "${CONFIG}" run "sudo chmod +x ${INSTALL_CMD}"
    multissh -c "${CONFIG}" run "sudo ${INSTALL_CMD}"
    echo "  ✅ Installation complete"
else
    echo "[4/4] No install command specified, skipping"
fi

# ── Cleanup local archive ───────────────────────────────
rm -f "${ARCHIVE}"

echo ""
echo "========================================"
echo "  ✅ ${TOOL_NAME} deployed to all hosts"
echo "  Remote location: ${REMOTE_DIR}"
echo "========================================"
