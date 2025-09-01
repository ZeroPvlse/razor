#!/usr/bin/env bash
set -euo pipefail

GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; NC="\033[0m"
info(){ echo -e "${GREEN}[+]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }
err(){  echo -e "${RED}[-]${NC} $*"; }

if [[ "$(id -u)" -ne 0 ]]; then
  warn "this script needs root to install globally. re-running with sudo..."
  exec sudo -E bash "$0" "$@"
fi

command -v apt >/dev/null 2>&1 || { err "apt not found. this script targets Kali/Debian."; exit 1; }

info "updating package lists..."
apt update -y

info "installing prerequisites: python3, pip, pipx..."
DEBIAN_FRONTEND=noninteractive apt install -y python3 python3-pip pipx

info "ensuring global pipx path is configured..."
pipx ensurepath --global || true  # continues even if it's already set

if pipx list | grep -q "^package XSStrike" || pipx list | grep -qi "^package xsstrike"; then
  info "XSStrike already installed. Upgrading to latest..."
  pipx upgrade xsstrike || pipx reinstall xsstrike
else
  info "installing XSStrike globally with pipx..."
  pipx install xsstrike
fi

BIN="/usr/local/bin/xsstrike"
if [[ -x "$BIN" ]]; then
  info "binary found at $BIN"
else
  if command -v xsstrike >/dev/null 2>&1; then
    BIN="$(command -v xsstrike)"
    info "binary resolved via PATH at $BIN"
  else
    err "xsstrike binary not found in PATH. something went wrong."
    exit 1
  fi
fi

info "running smoke test: xsstrike -h"
if xsstrike -h >/dev/null 2>&1; then
  info "XSStrike is working."
else
  warn "XSStrike installed but couldn't run a help check. check python compatibility."
fi

cat <<EOF

${GREEN}success!${NC}
XSStrike is installed

  Binary: $(command -v xsstrike)
  Venv:   /usr/local/pipx/venvs/xsstrike  (managed by pipx)

maintenance:
  sudo pipx upgrade xsstrike      # upgrade to latest
  sudo pipx uninstall xsstrike    # remove
  pipx list                       # view installed pipx packages
EOF

