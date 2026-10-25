# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared cwd-.env load policy for CLI and chat.

Blocks credential, security-posture, and interpreter/runtime injection variables
so a planted ``.env`` cannot pivot the operator process (RH-04 residuals).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Credential-bearing name fragments; use ``siyarix auth set-key`` / CredentialStore.
API_KEY_PATTERNS: tuple[str, ...] = (
    "_API_KEY",
    "_SECRET",
    "_PASSWORD",
    "_TOKEN",
    "_AUTH",
    "_BEARER",
    "_COOKIE",
    "_SESSION",
    "_CREDENTIAL",
    "_WEBHOOK",
    "_PRIVATE_KEY",
    "_ACCESS_KEY",
    "_MASTER_PASSWORD",
    "_MASTER_KEY",
    "_PASSPHRASE",
    "_URI",
    "_URL",
    "_DSN",
    "DATABASE_URL",
    "SSLKEYLOGFILE",
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "CONNECTION_STRING",
    "ENCRYPTION_KEY",
    "APP_KEY",
    "RAILS_MASTER_KEY",
)

PROVIDER_SHORT_KEYS: frozenset[str] = frozenset(
    {
        "OPENAI_KEY",
        "ANTHROPIC_KEY",
        "XAI_KEY",
        "GROQ_KEY",
        "GEMINI_KEY",
        "OPENROUTER_KEY",
        "TOGETHER_KEY",
        "COHERE_KEY",
        "MISTRAL_KEY",
        "DEEPSEEK_KEY",
        "PERPLEXITY_KEY",
        "HUGGINGFACE_KEY",
        "HF_KEY",
    }
)

# Exact names that must never load from cwd/.config .env.
BLOCKED_EXACT: frozenset[str] = frozenset(
    {
        "PGPASSWORD",
        "MYSQL_PWD",
        "DATABASE_URL",
        "REDIS_URL",
        "MONGO_URL",
        "MONGODB_URI",
        "API_KEY",
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "AUTH_TOKEN",
        "ACCESS_TOKEN",
        "CONNECTION_STRING",
        "SIYARIX_SAFE_MODE",
        "SIYARIX_PREAUTHORIZED",
        "SIYARIX_COMMAND_REVIEW",
        "SIYARIX_ALLOWED_SCOPE",
        "SIYARIX_CONFIG",
        "SIYARIX_CONFIG_DIR",
        # Security posture / trust gates must not flip via planted .env (RH-11).
        "SIYARIX_TRUST_PLUGINS",
        "SIYARIX_PLUGIN_AUTO_PIP",
        "SIYARIX_EXPERIMENTAL_SWARM",
        "SIYARIX_PERMISSION_GATE",
        "SIYARIX_PERMISSION_GATE_ENABLED",
        "SIYARIX_KMS_PROVIDER",
        "SIYARIX_MASTER_PASSWORD",
        "SIYARIX_MASTER_KEY",
        "SIYARIX_VAULT_PASSWORD",
        "SIYARIX_SUDO_PASSWORD",
        "PRIVATE_KEY",
        "OPENSSL_CONF",
        "DOCKER_HOST",
        "KUBECONFIG",
        "GIT_SSH_COMMAND",
        "GIT_SSH",
        "GIT_PROXY_COMMAND",
        "PGPASSFILE",
        "MYSQL_HISTFILE",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "NETRC",
        "HOME",
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_EXTERNAL_DIFF",
        "NPM_CONFIG_REGISTRY",
        "NPM_CONFIG_SCRIPT_SHELL",
        "PGSERVICEFILE",
        "DSN",
        "GIT_SSL_NO_VERIFY",
        "PYTHONHTTPSVERIFY",
        "NODE_EXTRA_CA_CERTS",
        "GIT_SSL_CAINFO",
        "AWS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "DOCKER_CERT_PATH",
        "DOCKER_TLS_VERIFY",
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "PIP_TRUSTED_HOST",
        "NPM_CONFIG_STRICT_SSL",
        "COMPOSER_DISABLE_TLS",
        "UV_INSECURE_HOST",
        "LESSOPEN",
        "SUDO_ASKPASS",
        "GCONV_PATH",
        "HOSTALIASES",
        "GIT_HTTP_PROXY",
        "GIT_HTTPS_PROXY",
        "FTP_PROXY",
        "SOCKS_PROXY",
        "SOCKS5_PROXY",
        "ALL_PROXY",
        "KUBE_CONFIG_PATH",
        "KUBE_CONFIG",
        "GIT_EXEC_PATH",
        "RSYNC_RSH",
        "RSYNC_CONNECT_PROG",
        "RSYNC_PROXY",
        "OPENSSL_MODULES",
        "OPENSSL_ENGINES",
        "WGETRC",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "JAVA_OPTS",
        "PERL5DB",
        "DOTNET_STARTUP_HOOKS",
        "CORECLR_PROFILER_PATH",
        "CORECLR_PROFILER_PATH_64",
        "CORECLR_PROFILER_PATH_32",
        "CORECLR_ENABLE_PROFILING",
        "CORECLR_PROFILER",
        "DOTNET_ADDITIONALDEPS",
        "HOSTFILE",
        "CVS_RSH",
        "ZDOTDIR",
        "CONTAINER_HOST",
        "DOCKER_CONFIG",
        "RAILS_MASTER_KEY",
        "ENCRYPTION_KEY",
        "APP_KEY",
        "CLASSPATH",
        "JAVA_OPTIONS",
        "IBM_JAVA_OPTIONS",
        "OPENJ9_JAVA_OPTIONS",
        "CATALINA_OPTS",
        "MSBUILDSTARTUPHOOKS",
        "SOCKS5_SERVER",
        "GIT_SSL_CAPATH",
        "DOCKER_CONTEXT",
        "NODE_PATH",
        "PHPRC",
        "MAVEN_OPTS",
        "ANSIBLE_SSH_ARGS",
        "ANSIBLE_INVENTORY",
        "ANSIBLE_CONFIG",
        "ANSIBLE_SSH_EXECUTABLE",
        "ANSIBLE_ACTION_PLUGINS",
        "ANSIBLE_LIBRARY",
        "ANSIBLE_LOOKUP_PLUGINS",
        "ANSIBLE_FILTER_PLUGINS",
        "ANSIBLE_CALLBACK_PLUGINS",
        "VIMINIT",
        "GRADLE_OPTS",
        "SBT_OPTS",
        "SVN_SSH",
        "EXINIT",
        "RUSTC_WRAPPER",
        "PYTHONBREAKPOINT",
        "LUA_INIT",
        "LUA_PATH",
        "LUA_CPATH",
        "CCACHE_PREFIX",
        "SOCKS_SERVER",
        "HELM_KUBEAPISERVER",
        "RUSTC",
        "WINELOADER",
        "MAKEFILES",
        "PODMAN_HOST",
        "GOCACHEPROG",
        "PYTHONEXECUTABLE",
        "BUILDKIT_HOST",
        "RES_OPTIONS",
        "BOTO_CONFIG",
        "AWS_CONFIG_FILE",
        "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE",
        "EDITOR",
        "VISUAL",
        "SUDO_EDITOR",
        "GIT_EDITOR",
        "FCEDIT",
        "SELECTED_EDITOR",
        # Interpreter / toolkit plugin-path pivots (RH-12).
        "QT_PLUGIN_PATH",
        "QT_QPA_PLATFORM_PLUGIN_PATH",
        "GST_PLUGIN_PATH",
        "GST_PLUGIN_SYSTEM_PATH",
        "GIO_MODULE_DIR",
        "GI_TYPELIB_PATH",
        "PYTHONUSERBASE",
        "PYTHON_EGG_CACHE",
        "NUGET_PLUGIN_PATHS",
        "APPDOMAIN_MANAGER_ASM",
        "APPDOMAIN_MANAGER_TYPE",
        "MONO_PATH",
        "MONO_CFG_DIR",
        "PHP_INI_SCAN_DIR",
        "GEM_HOME",
        "GEM_PATH",
        "BUNDLE_PATH",
        "GOPROXY",
        "GOPATH",
        "GOROOT",
        "PACKER_PLUGIN_PATH",
        "TF_PLUGIN_CACHE_DIR",
        "TERRAFORM_PLUGIN_DIR",
        "ANSIBLE_COLLECTIONS_PATHS",
        "PIPEWIRE_MODULE_DIR",
        "LADSPA_PATH",
        "LV2_PATH",
        "VST_PATH",
        "LIBRARY_PATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "PKG_CONFIG_PATH",
        "KUBE_EDITOR",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "RUSTC_WRAPPER",
        "GTK_MODULES",
        "GTK3_MODULES",
        "GTK2_MODULES",
        "GIO_EXTRA_MODULES",
        "MAGICK_CODER_MODULE_PATH",
        "MAGICK_CODER_FILTER_PATH",
        "MAGICK_HOME",
        "KUBECTL_EXTERNAL_DIFF",
    }
)

# Interpreter / linker injection names (also matched case-sensitively for proxies).
BLOCKED_VARS: frozenset[str] = frozenset(
    {
        "PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "BASH_ENV",
        "IFS",
        "SHELLOPTS",
        "PERL5LIB",
        "PERLLIB",
        "PERL5OPT",
        "PERL5DB",
        "RUBYLIB",
        "RUBYOPT",
        "PYTHONHOME",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "NODE_OPTIONS",
        "PYTHONWARNINGS",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "JAVA_OPTS",
        "IBM_JAVA_OPTIONS",
        "OPENJ9_JAVA_OPTIONS",
        "CATALINA_OPTS",
        "ENV",
        "PROMPT_COMMAND",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "SSLKEYLOGFILE",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "CURL_HOME",
        "OPENSSL_CONF",
        "OPENSSL_MODULES",
        "OPENSSL_ENGINES",
        "WGETRC",
        "DOCKER_HOST",
        "KUBECONFIG",
        "KUBE_CONFIG",
        "GIT_SSH_COMMAND",
        "GIT_SSH",
        "GIT_PROXY_COMMAND",
        "PGPASSFILE",
        "NETRC",
        "HOME",
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_EXTERNAL_DIFF",
        "NPM_CONFIG_REGISTRY",
        "NPM_CONFIG_SCRIPT_SHELL",
        "PGSERVICEFILE",
        "GIT_SSL_NO_VERIFY",
        "PYTHONHTTPSVERIFY",
        "NODE_EXTRA_CA_CERTS",
        "GIT_SSL_CAINFO",
        "AWS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "DOCKER_CERT_PATH",
        "DOCKER_TLS_VERIFY",
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "PIP_TRUSTED_HOST",
        "NPM_CONFIG_STRICT_SSL",
        "COMPOSER_DISABLE_TLS",
        "UV_INSECURE_HOST",
        "LESSOPEN",
        "SUDO_ASKPASS",
        "GCONV_PATH",
        "HOSTALIASES",
        "GIT_HTTP_PROXY",
        "GIT_HTTPS_PROXY",
        "FTP_PROXY",
        "SOCKS_PROXY",
        "SOCKS5_PROXY",
        "ftp_proxy",
        "socks_proxy",
        "socks5_proxy",
        "KUBE_CONFIG_PATH",
        "GIT_EXEC_PATH",
        "RSYNC_RSH",
        "RSYNC_CONNECT_PROG",
        "RSYNC_PROXY",
        "DOTNET_STARTUP_HOOKS",
        "CORECLR_PROFILER_PATH",
        "CORECLR_PROFILER_PATH_64",
        "CORECLR_PROFILER_PATH_32",
        "CORECLR_ENABLE_PROFILING",
        "CORECLR_PROFILER",
        "GOCACHEPROG",
        "PYTHONEXECUTABLE",
        "BUILDKIT_HOST",
        "RES_OPTIONS",
        "BOTO_CONFIG",
        "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE",
        "EDITOR",
        "VISUAL",
        "SUDO_EDITOR",
        "GIT_EDITOR",
        "LUA_PATH",
        "LUA_CPATH",
        "ANSIBLE_ACTION_PLUGINS",
        "ANSIBLE_LIBRARY",
        "HOSTFILE",
        "CVS_RSH",
        "ZDOTDIR",
        "CONTAINER_HOST",
        "DOCKER_CONFIG",
        "CLASSPATH",
        "JAVA_OPTIONS",
        "MSBUILDSTARTUPHOOKS",
        "SOCKS5_SERVER",
        "GIT_SSL_CAPATH",
        "DOCKER_CONTEXT",
        "NODE_PATH",
        "PHPRC",
        "MAVEN_OPTS",
        "ANSIBLE_SSH_ARGS",
        "ANSIBLE_INVENTORY",
        "ANSIBLE_CONFIG",
        "ANSIBLE_SSH_EXECUTABLE",
        "VIMINIT",
        "GRADLE_OPTS",
        "SBT_OPTS",
        "SVN_SSH",
        "EXINIT",
        "RUSTC_WRAPPER",
        "PYTHONBREAKPOINT",
        "LUA_INIT",
        "CCACHE_PREFIX",
        "SOCKS_SERVER",
        "HELM_KUBEAPISERVER",
        "RUSTC",
        "WINELOADER",
        "MAKEFILES",
        "PODMAN_HOST",
        "QT_PLUGIN_PATH",
        "QT_QPA_PLATFORM_PLUGIN_PATH",
        "GST_PLUGIN_PATH",
        "GST_PLUGIN_SYSTEM_PATH",
        "GIO_MODULE_DIR",
        "GI_TYPELIB_PATH",
        "PYTHONUSERBASE",
        "NUGET_PLUGIN_PATHS",
        "APPDOMAIN_MANAGER_ASM",
        "APPDOMAIN_MANAGER_TYPE",
        "MONO_PATH",
        "PHP_INI_SCAN_DIR",
        "GEM_HOME",
        "GEM_PATH",
        "GOPROXY",
        "PACKER_PLUGIN_PATH",
        "TF_PLUGIN_CACHE_DIR",
        "LIBRARY_PATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "PKG_CONFIG_PATH",
        "KUBE_EDITOR",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "GTK_MODULES",
        "GTK3_MODULES",
        "GTK2_MODULES",
        "GIO_EXTRA_MODULES",
        "MAGICK_CODER_MODULE_PATH",
        "MAGICK_CODER_FILTER_PATH",
        "KUBECTL_EXTERNAL_DIFF",
        "HELM_KUBECONFIG",
        "CC",
        "CXX",
        "CPP",
        "TCLLIBPATH",
        "TCL_LIBRARY",
        "TK_LIBRARY",
        # Browser / language / package / proxy pivots (RH-36).
        "BROWSER",
        "GUILE_LOAD_PATH",
        "GUILE_LOAD_COMPILED_PATH",
        "PIP_FIND_LINKS",
        "PIP_EXTRA_INDEX_URL",
        "PIP_INDEX_URL",
        "GRPC_PROXY",
        "grpc_proxy",
        "VAULT_ADDR",
        "VAULT_AGENT_ADDR",
        "GDK_PIXBUF_MODULEDIR",
        "GDK_PIXBUF_MODULE_FILE",
        "NSS_WRAPPER_PASSWD",
        "NSS_WRAPPER_GROUP",
        "ELECTRON_RUN_AS_NODE",
        "ELECTRON_NO_ASAR",
        # Proxy / mitm config pivots (RH-39).
        "MITMPROXY_CONFDIR",
        "MITMPROXY_CONF",
        "REDSOCKS_CONF",
        "MICROSOCKS_CONFIG",
        # Service-discovery / DB hosts also blocked on argv under scope (RH-41).
        "CONSUL_HTTP_ADDR",
        "CONSUL_HTTP_HOST",
        "NOMAD_ADDR",
        "ETCDCTL_ENDPOINTS",
        "CLICKHOUSE_HOST",
        "CASSANDRA_HOST",
        "SSH_PROXY_COMMAND",
        "YARN_REGISTRY",
        "PNPM_REGISTRY",
        "UV_INDEX",
        "UV_EXTRA_INDEX_URL",
        "UV_DEFAULT_INDEX",
        "NPM_CONFIG_REGISTRY",
        # Container / pip config pivots (RH-42).
        "CONTAINERD_ADDRESS",
        "CONTAINERD_NAMESPACE",
        "PIP_CONFIG_FILE",
        "PIP_CACHE_DIR",
        "COMPOSE_FILE",
        "DOCKER_CONTEXT",
        # DB transport hosts (RH-43) — same set blocked on argv under scope.
        "PGHOST",
        "PGHOSTADDR",
        "PGPORT",
        "PGSERVICE",
        "PGSERVICEFILE",
        "MYSQL_HOST",
        "MYSQL_UNIX_PORT",
        "REDIS_HOST",
        "MONGO_URL",
        "MONGODB_URI",
        # VPN / mesh client pivots (RH-44).
        "WG_CONF",
        "WIREGUARD_INTERFACE",
        "OPENVPN_CONFIG",
        "TAILSCALE_AUTHKEY",
        "TS_AUTHKEY",
        "CLASH_HOME",
        "SING_BOX_CONFIG",
    }
)


def should_skip_dotenv_key(key: str) -> bool:
    """Return True when *key* must not be loaded from a .env file."""
    if not key:
        return True
    key_upper = key.upper()
    # Exported bash functions: ``BASH_FUNC_foo%%``.
    if key_upper.startswith("BASH_FUNC_") or key.endswith("%%"):
        return True
    if key_upper.startswith("GIT_CONFIG_"):
        return True
    if key_upper.startswith("SIYARIX_") and key_upper.endswith("_KEY"):
        return True
    # Any SIYARIX_* security/posture toggle from planted .env (RH-11).
    if key_upper.startswith("SIYARIX_"):
        return True
    if key_upper.startswith("CORECLR_") or key_upper.startswith("DOTNET_"):
        return True
    if key_upper.startswith("ANSIBLE_") and (
        "PLUGIN" in key_upper or key_upper.endswith("_LIBRARY") or "MODULE" in key_upper
    ):
        return True
    # Broad plugin/module path pivots (RH-12 / RH-18 / RH-23), including versioned
    # suffixes like ``GST_PLUGIN_SYSTEM_PATH_1_0``.
    if "PLUGIN" in key_upper and (
        "_PATH" in key_upper
        or key_upper.endswith(("_DIR", "_HOME", "_DIRS", "_PATHS"))
    ):
        return True
    if key_upper.endswith("_MODULES") or key_upper.endswith("_MODULE_PATH"):
        return True
    if key_upper.endswith("_RUSTC_WRAPPER") or key_upper.endswith("RUSTC_WRAPPER"):
        return True
    if key_upper.endswith("_EXTERNAL_DIFF"):
        return True
    if key_upper.endswith("_KUBECONFIG") or key_upper == "HELM_KUBECONFIG":
        return True
    if key_upper in {"CC", "CXX", "CPP", "LD", "AS", "FC"}:
        return True
    if key_upper.endswith("LIBPATH") or key_upper.endswith("_LIBRARY"):
        return True
    if key_upper.endswith("_LOAD_PATH") or key_upper.endswith("_FIND_LINKS"):
        return True
    if key_upper.endswith("_PIXBUF_MODULEDIR") or key_upper.startswith("NSS_WRAPPER_"):
        return True
    if key_upper.startswith("ELECTRON_"):
        return True
    if key_upper in {"BROWSER", "VAULT_ADDR", "GRPC_PROXY"}:
        return True
    if key_upper.endswith("_CONFDIR") or key_upper in {
        "REDSOCKS_CONF",
        "MITMPROXY_CONF",
        "MICROSOCKS_CONFIG",
    }:
        return True
    if key_upper.endswith("_REGISTRY") or key_upper in {
        "UV_INDEX",
        "UV_EXTRA_INDEX_URL",
        "UV_DEFAULT_INDEX",
        "CONSUL_HTTP_ADDR",
        "CONSUL_HTTP_HOST",
        "NOMAD_ADDR",
        "ETCDCTL_ENDPOINTS",
        "CLICKHOUSE_HOST",
        "CASSANDRA_HOST",
        "SSH_PROXY_COMMAND",
        "CONTAINERD_ADDRESS",
        "CONTAINERD_NAMESPACE",
        "PIP_CONFIG_FILE",
        "COMPOSE_FILE",
        "DOCKER_CONTEXT",
    }:
        return True
    if key_upper.startswith("CONTAINERD_") or key_upper.startswith("PIP_"):
        return True
    # libpq / mysql client transport pivots (RH-43).
    if key_upper in {
        "PGHOST",
        "PGHOSTADDR",
        "PGPORT",
        "PGSERVICE",
        "PGSERVICEFILE",
        "PGDATABASE",
        "PGUSER",
        "PGPASSWORD",
        "PGSSLMODE",
        "MYSQL_HOST",
        "MYSQL_UNIX_PORT",
        "REDIS_HOST",
        "MONGO_URL",
        "MONGODB_URI",
        "DATABASE_URL",
        "SQLALCHEMY_DATABASE_URI",
        "WG_CONF",
        "WIREGUARD_INTERFACE",
        "OPENVPN_CONFIG",
        "TAILSCALE_AUTHKEY",
        "TS_AUTHKEY",
        "CLASH_HOME",
        "SING_BOX_CONFIG",
    }:
        return True
    if key_upper.startswith("TAILSCALE_") or key_upper.startswith("WIREGUARD_"):
        return True
    if key_upper.startswith("OPENVPN_") or key_upper.startswith("CLASH_"):
        return True
    if key_upper.endswith("_EDITOR") and key_upper not in {""}:
        # KUBE_EDITOR / GIT_EDITOR / etc. — editor injection from planted .env.
        if key_upper in {
            "KUBE_EDITOR",
            "GIT_EDITOR",
            "EDITOR",
            "VISUAL",
            "SUDO_EDITOR",
            "FCEDIT",
            "SELECTED_EDITOR",
            "SVN_EDITOR",
            "HGEDITOR",
        } or key_upper.endswith("_EDITOR"):
            return True
    if key_upper in BLOCKED_EXACT or key_upper in PROVIDER_SHORT_KEYS:
        return True
    if key in BLOCKED_VARS or key_upper in BLOCKED_VARS:
        return True
    if any(p in key_upper for p in API_KEY_PATTERNS):
        return True
    return False


def apply_dotenv_file(env_path: Path) -> None:
    """Load non-blocked key=value pairs from *env_path* into ``os.environ``."""
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip("'").strip('"')
        if not key or os.environ.get(key):
            continue
        if should_skip_dotenv_key(key):
            logger.debug("Skipping blocked/sensitive env var %s from .env", key)
            continue
        os.environ[key] = val


__all__ = [
    "API_KEY_PATTERNS",
    "BLOCKED_EXACT",
    "BLOCKED_VARS",
    "PROVIDER_SHORT_KEYS",
    "apply_dotenv_file",
    "should_skip_dotenv_key",
]
