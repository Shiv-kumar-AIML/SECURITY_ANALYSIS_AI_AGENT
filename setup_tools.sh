#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# setup_tools.sh — Pre-deployment tool installer for SECURITY_ANALYSIS_AI_AGENT
#
# Run this ONCE before activating your virtualenv / installing Python deps.
# It installs the system-level CLI tools that the agent invokes via subprocess.
#
# Tools handled here        | Why not in pyproject.toml?
# --------------------------|--------------------------------------------------
# trivy                     | Aqua Security binary — not a Python package
# gitleaks                  | Go binary — not a Python package
# node / npm                | JavaScript runtime — not a Python package
# git                       | Core system dependency
#
# Tools NOT handled here (installed automatically by pip via pyproject.toml):
#   semgrep, bandit         → `pip install -e .` OR `pip install semgrep bandit`
#   tree-sitter-*           → installed as Python packages
#
# Usage:
#   chmod +x setup_tools.sh
#   ./setup_tools.sh
# ---------------------------------------------------------------------------

set -euo pipefail

# ── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Privilege check ──────────────────────────────────────────────────────────
SUDO=""
if [[ $EUID -ne 0 ]]; then
  if command -v sudo &>/dev/null; then
    SUDO="sudo"
    info "Not running as root — will use sudo for system installs."
  else
    error "Not running as root and 'sudo' not found. Re-run as root or install sudo."
    exit 1
  fi
fi

# ── Distro detection ─────────────────────────────────────────────────────────
if [[ -f /etc/os-release ]]; then
  # shellcheck source=/dev/null
  source /etc/os-release
  DISTRO_ID="${ID:-unknown}"
  DISTRO_ID_LIKE="${ID_LIKE:-}"
else
  DISTRO_ID="unknown"
  DISTRO_ID_LIKE=""
fi

is_debian_based() {
  [[ "$DISTRO_ID" == "debian" || "$DISTRO_ID" == "ubuntu" || \
     "$DISTRO_ID_LIKE" == *"debian"* || "$DISTRO_ID_LIKE" == *"ubuntu"* ]]
}
is_rpm_based() {
  [[ "$DISTRO_ID" == "fedora" || "$DISTRO_ID" == "rhel" || \
     "$DISTRO_ID" == "centos" || "$DISTRO_ID" == "rocky" || \
     "$DISTRO_ID" == "almalinux" || "$DISTRO_ID_LIKE" == *"rhel"* || \
     "$DISTRO_ID_LIKE" == *"fedora"* ]]
}

# ── Helper: check if a binary is already installed ───────────────────────────
require() {
  local bin="$1"
  if command -v "$bin" &>/dev/null; then
    success "$bin already installed: $(command -v "$bin")"
    return 0
  fi
  return 1
}

# ── 1. git ───────────────────────────────────────────────────────────────────
echo
info "━━━ [1/5] git ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if ! require git; then
  if is_debian_based; then
    $SUDO apt-get update -qq && $SUDO apt-get install -y git
  elif is_rpm_based; then
    $SUDO dnf install -y git
  else
    error "Cannot auto-install git on '$DISTRO_ID'. Install it manually."
    exit 1
  fi
  success "git installed: $(git --version)"
fi

# ── 2. trivy ─────────────────────────────────────────────────────────────────
echo
info "━━━ [2/5] trivy (Aqua Security vulnerability scanner) ━━━━━━━━━━━━━━━━━━"
if ! require trivy; then
  if is_debian_based; then
    info "Adding trivy apt repository..."
    $SUDO apt-get install -y wget apt-transport-https gnupg lsb-release
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
      | gpg --dearmor \
      | $SUDO tee /usr/share/keyrings/trivy.gpg > /dev/null
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
      | $SUDO tee /etc/apt/sources.list.d/trivy.list > /dev/null
    $SUDO apt-get update -qq && $SUDO apt-get install -y trivy
  elif is_rpm_based; then
    info "Adding trivy rpm repository..."
    cat <<'EOF' | $SUDO tee /etc/yum.repos.d/trivy.repo > /dev/null
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF
    $SUDO dnf install -y trivy
  else
    info "Distro '$DISTRO_ID' not recognised — falling back to trivy install script..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | $SUDO sh -s -- -b /usr/local/bin
  fi
  success "trivy installed: $(trivy --version | head -1)"
fi

# ── 3. gitleaks ──────────────────────────────────────────────────────────────
echo
info "━━━ [3/5] gitleaks (secret / credential leak scanner) ━━━━━━━━━━━━━━━━━"
if ! require gitleaks; then
  info "Fetching latest gitleaks release from GitHub..."
  GITLEAKS_VERSION=$(
    curl -fsSL "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" \
      | grep '"tag_name"' | sed 's/.*"tag_name": *"v\([^"]*\)".*/\1/'
  )
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64)  GL_ARCH="x64" ;;
    aarch64) GL_ARCH="arm64" ;;
    armv7*)  GL_ARCH="armv7" ;;
    *)       error "Unsupported architecture: $ARCH"; exit 1 ;;
  esac
  GL_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz"
  info "Downloading gitleaks v${GITLEAKS_VERSION} (${GL_ARCH})..."
  TMP_DIR=$(mktemp -d)
  curl -fsSL "$GL_URL" -o "${TMP_DIR}/gitleaks.tar.gz"
  tar -xzf "${TMP_DIR}/gitleaks.tar.gz" -C "${TMP_DIR}"
  $SUDO mv "${TMP_DIR}/gitleaks" /usr/local/bin/gitleaks
  $SUDO chmod +x /usr/local/bin/gitleaks
  rm -rf "${TMP_DIR}"
  success "gitleaks installed: $(gitleaks version)"
fi

# ── 4. node / npm ────────────────────────────────────────────────────────────
echo
info "━━━ [4/4] node / npm (required for npm audit of JS projects) ━━━━━━━━━━"
if ! require node || ! require npm; then
  if is_debian_based; then
    # NodeSource LTS (v20) — avoids the outdated apt default
    info "Installing Node.js 20 LTS via NodeSource..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | $SUDO bash -
    $SUDO apt-get install -y nodejs
  elif is_rpm_based; then
    curl -fsSL https://rpm.nodesource.com/setup_20.x | $SUDO bash -
    $SUDO dnf install -y nodejs
  else
    if command -v snap &>/dev/null; then
      $SUDO snap install node --classic --channel=20
    else
      error "Cannot auto-install Node.js on '$DISTRO_ID'. Install it manually (https://nodejs.org)."
      exit 1
    fi
  fi
  success "node installed: $(node --version)   npm: $(npm --version)"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  All system tools installed successfully!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo "  Next steps:"
echo "    1.  Create and activate your virtualenv:"
echo "          python -m venv .venv && source .venv/bin/activate"
echo
echo "    2.  Install Python dependencies (includes semgrep + bandit as CLIs):"
echo "          pip install -e ."
echo
echo "    3.  Copy and fill in your API keys:"
echo "          cp .env.example .env   # (or create .env manually)"
echo
echo "    4.  Run the app:"
echo "          streamlit run streamlit_app.py"
echo "          # or CLI:"
echo "          python main.py --target ./workspace/testing_repo"
echo
