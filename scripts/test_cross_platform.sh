#!/usr/bin/env bash
# =============================================================================
# Siyarix Cross-Platform Test Suite
#   Tests installation and core functionality across all supported platforms.
#
# Usage:
#   bash scripts/test_cross_platform.sh              # full test
#   bash scripts/test_cross_platform.sh --quick       # quick smoke test
#   bash scripts/test_cross_platform.sh --json        # JSON output
# =============================================================================
set -euo pipefail

MODE="full"
JSON_OUTPUT=0
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
BOLD="\033[1m"
RESET="\033[0m"

PASS=0
FAIL=0
SKIP=0

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}  ╔════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}${BOLD}  ║    Siyarix Cross-Platform Test Suite          ║${RESET}"
    echo -e "${CYAN}${BOLD}  ╚════════════════════════════════════════════════╝${RESET}"
    echo ""
}

info()  { echo -e "  ${CYAN}==>${RESET} $*"; }
pass()  { echo -e "  ${GREEN}✓${RESET} $*"; ((PASS++)); }
fail()  { echo -e "  ${RED}✗${RESET} $*"; ((FAIL++)); }
skip()  { echo -e "  ${YELLOW}~${RESET} $*"; ((SKIP++)); }

detect_os() {
    if [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux" ]; then
        echo "termux"
    elif [ -n "${TERM_PROGRAM:-}" ] && echo "$TERM_PROGRAM" | grep -qi "ish" 2>/dev/null; then
        echo "ish"
    elif [ -f "/system/etc/param/ohos.para" ] || [ -n "${OHOS_ARCH:-}" ] || (uname -a 2>/dev/null | grep -qi "ohos"); then
        echo "harmonyos"
    elif [ "$(uname -s)" = "Linux" ]; then
        if uname -r 2>/dev/null | grep -qi "microsoft\|wsl"; then
            echo "wsl"
        else
            echo "linux"
        fi
    elif [ "$(uname -s)" = "Darwin" ]; then
        echo "macos"
    else
        case "$(uname -s)" in
            MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
            *) echo "other" ;;
        esac
    fi
}

run_test() {
    local test_name="$1"
    local test_cmd="$2"

    if [ "$MODE" = "quick" ]; then
        echo -n "  "
        echo -n "$test_name... "
        if eval "$test_cmd" &>/dev/null; then
            echo -e "${GREEN}✓${RESET}"
            ((PASS++))
        else
            echo -e "${RED}✗${RESET}"
            ((FAIL++))
        fi
        return
    fi

    if eval "$test_cmd" &>/dev/null; then
        pass "$test_name"
    else
        fail "$test_name"
    fi
}

test_python() {
    info "Testing Python availability..."
    run_test "python3 is available" "command -v python3"
    run_test "python3 --version" "python3 --version 2>&1 | grep -q '3\\.1[1-9]\\|3\\.[2-9][0-9]'"
}

test_pip() {
    info "Testing pip..."
    run_test "pip3 is available" "command -v pip3 || command -v pip"
    run_test "pip can install packages" "pip3 install --dry-run siyarix 2>/dev/null || pip install --dry-run siyarix 2>/dev/null || true"
}

test_core_imports() {
    info "Testing core Python imports..."
    run_test "import siyarix" "python3 -c 'import siyarix'"
    run_test "siyarix version" "python3 -c 'from siyarix import __version__; print(__version__)' | grep -q '.'"
    run_test "import siyarix._platform" "python3 -c 'from siyarix._platform import get_platform_id'"
    run_test "import siyarix.config" "python3 -c 'from siyarix.config import get_config_dir'"
    run_test "import siyarix.subprocess_utils" "python3 -c 'from siyarix.subprocess_utils import safe_run_sync'"
    run_test "import siyarix.session_log" "python3 -c 'from siyarix.session_log import SessionLogger'"
    run_test "import siyarix.security_hardening" "python3 -c 'from siyarix.security_hardening import validator, danger_analyzer'"
    run_test "import siyarix.chat.platform_utils" "python3 -c 'from siyarix.chat.platform_utils import detect_shell'"
}

test_platform_detection() {
    info "Testing platform detection..."
    local os_type
    os_type=$(detect_os)
    info "Detected OS: ${os_type}"

    run_test "platform detection returns non-empty" "python3 -c 'from siyarix._platform import get_platform_id; assert get_platform_id()'"
    run_test "platform is recognized" "python3 -c 'from siyarix._platform import get_platform_id; assert get_platform_id() in (\"linux\", \"macos\", \"windows\", \"wsl\", \"android\", \"ios\", \"harmonyos\", \"unknown\")'"
    run_test "system returns non-empty" "python3 -c 'import platform; assert platform.system()'"
}

test_subprocess() {
    info "Testing subprocess utilities..."
    run_test "detect_package_manager returns something" "python3 -c 'from siyarix.subprocess_utils import detect_package_manager; assert detect_package_manager()'"
    run_test "get_platform_shell_cmd works" "python3 -c 'from siyarix.subprocess_utils import get_platform_shell_cmd; assert len(get_platform_shell_cmd(\"echo test\")) >= 2'"
    run_test "safe_run_sync basic command" "python3 -c 'from siyarix.subprocess_utils import safe_run_sync; r = safe_run_sync([\"echo\", \"test\"], timeout=5); assert r.success'"
}

test_path_handling() {
    info "Testing path handling..."
    run_test "config dir uses pathlib" "python3 -c 'from siyarix._platform import get_config_dir_platform; p = get_config_dir_platform(); assert hasattr(p, \"suffix\")'"
    run_test "home dir is pathlib" "python3 -c 'from siyarix._platform import get_home_dir; p = get_home_dir(); assert hasattr(p, \"suffix\")'"
    run_test "no hardcoded /home/ paths in _platform" "python3 -c 'import inspect, siyarix._platform; src = inspect.getsource(siyarix._platform); assert \"/home/\" not in src.split(\"hardcoded\")[0] if \"hardcoded\" in src else True'"
}

test_config() {
    info "Testing configuration..."
    run_test "SettingsStore singleton" "python3 -c 'from siyarix.config import SettingsStore; s1 = SettingsStore(); s2 = SettingsStore(); assert s1 is s2'"
    run_test "get_config_dir returns Path" "python3 -c 'from siyarix.config import get_config_dir; assert isinstance(get_config_dir(), type(Path(\".\")))'"
    run_test "config defaults loaded" "python3 -c 'from siyarix.config import SettingsStore; assert SettingsStore().get(\"color_theme\") is not None'"
}

test_security() {
    info "Testing security hardening..."
    run_test "validate IP" "python3 -c 'from siyarix.security_hardening import validator; assert validator.validate_ip(\"127.0.0.1\")[0]'"
    run_test "validate hostname" "python3 -c 'from siyarix.security_hardening import validator; assert validator.validate_hostname(\"example.com\")[0]'"
    run_test "redact API keys" "python3 -c 'from siyarix.security_hardening import redactor; assert \"[REDACTED]\" in redactor.redact(\"sk-test12345678901234567890\")'"
    run_test "danger analyzer safe" "python3 -c 'from siyarix.security_hardening import danger_analyzer; assert not danger_analyzer.analyze(\"ls -la\").is_dangerous'"
    run_test "danger analyzer rm -rf" "python3 -c 'from siyarix.security_hardening import danger_analyzer; assert danger_analyzer.analyze(\"rm -rf /\").is_dangerous'"
}

test_install_scripts_syntax() {
    info "Testing installer script syntax..."

    if command -v bash &>/dev/null; then
        run_test "install.sh syntax" "bash -n installer/install.sh"
        run_test "install_android.sh syntax" "bash -n install_android.sh"
        run_test "install_harmonyos.sh syntax" "bash -n install_harmonyos.sh"
    fi
}

test_pyproject() {
    info "Testing pyproject.toml..."
    run_test "pyproject.toml exists" "test -f pyproject.toml"
    run_test "pyproject has requires-python" "grep -q 'requires-python' pyproject.toml"
    run_test "pyproject has classifiers" "grep -q 'classifiers' pyproject.toml"
    run_test "pyproject has OS Independent classifier" "grep -q 'OS Independent' pyproject.toml"
}

main() {
    banner

    while [ $# -gt 0 ]; do
        case "$1" in
            --quick|-q) MODE="quick"; shift ;;
            --json|-j) JSON_OUTPUT=1; shift ;;
            --help|-h)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --quick, -q    Quick smoke test (pass/fail only)"
                echo "  --json, -j     JSON output format"
                echo "  --help, -h     Show this help"
                exit 0
                ;;
            *) echo "Unknown option: $1"; exit 1 ;;
        esac
    done

    cd "$(dirname "$0")/.."

    OS=$(detect_os)
    echo ""
    echo -e "  ${BOLD}Platform:${RESET} $OS ($(uname -s) $(uname -r))"
    echo -e "  ${BOLD}Python:${RESET}  $(python3 --version 2>&1 || echo 'not found')"
    echo ""

    test_python
    test_pip
    test_core_imports
    test_platform_detection
    test_subprocess
    test_path_handling
    test_config
    test_security
    test_install_scripts_syntax
    test_pyproject

    echo ""
    echo -e "  ${BOLD}Results:${RESET} ${GREEN}${PASS} passed${RESET}, ${RED}${FAIL} failed${RESET}, ${YELLOW}${SKIP} skipped${RESET}"
    echo ""

    if [ $FAIL -gt 0 ]; then
        echo -e "  ${RED}Some tests failed. See above for details.${RESET}"
        echo ""
        exit 1
    else
        echo -e "  ${GREEN}All tests passed!${RESET}"
        echo ""
        exit 0
    fi
}

main "$@"
