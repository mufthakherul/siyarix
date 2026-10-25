# SPDX-License-Identifier: AGPL-3.0-or-later
"""cwd .env must not flip security posture or inject interpreter hooks."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from siyarix.cli import _load_dotenv


def test_load_dotenv_skips_security_posture_and_inject_vars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "SIYARIX_SAFE_MODE=0",
                "SIYARIX_PREAUTHORIZED=1",
                "SIYARIX_COMMAND_REVIEW=false",
                "SIYARIX_ALLOWED_SCOPE=0.0.0.0/0",
                "PERL5OPT=-d:Foo",
                "PERLLIB=/tmp/evil",
                "RUBYOPT=-rfoo",
                "JAVA_TOOL_OPTIONS=-javaagent:x",
                "_JAVA_OPTIONS=-javaagent:x",
                "JDK_JAVA_OPTIONS=-javaagent:x",
                "JAVA_OPTS=-Xbootclasspath/a:/tmp/evil",
                "IBM_JAVA_OPTIONS=-javaagent:x",
                "OPENJ9_JAVA_OPTIONS=-javaagent:x",
                "CATALINA_OPTS=-javaagent:x",
                "PERL5DB=system('id')",
                "SOCKS5_PROXY=socks5://evil",
                "OPENSSL_MODULES=/tmp/evil",
                "OPENSSL_ENGINES=/tmp/evil",
                "WGETRC=/tmp/wgetrc",
                "KUBE_CONFIG=/tmp/evil.kube",
                "DOTNET_STARTUP_HOOKS=/tmp/evil",
                "DOTNET_AdditionalDeps=/tmp/evil",
                "CORECLR_PROFILER_PATH=/tmp/evil",
                "CORECLR_PROFILER_PATH_64=/tmp/evil",
                "CORECLR_ENABLE_PROFILING=1",
                "CORECLR_PROFILER={11111111-1111-1111-1111-111111111111}",
                "GOCACHEPROG=/tmp/evil",
                "BASH_FUNC_foo%%=() { id; }",
                "EDITOR=/tmp/pwn-editor",
                "SUDO_EDITOR=/tmp/pwn-editor",
                "ANSIBLE_ACTION_PLUGINS=/tmp/evil",
                "ANSIBLE_LIBRARY=/tmp/evil",
                "PYTHONEXECUTABLE=/tmp/pwn-python",
                "LUA_PATH=/tmp/evil/?.lua",
                "BUILDKIT_HOST=tcp://evil:1234",
                "RES_OPTIONS=attempts:1",
                "BOTO_CONFIG=/tmp/evil.boto",
                "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=/tmp/evil.pem",
                "HOSTFILE=/tmp/hosts",
                "CVS_RSH=ssh -o ProxyCommand=evil",
                "ZDOTDIR=/tmp/zdot",
                "CONTAINER_HOST=tcp://evil:2375",
                "DOCKER_CONFIG=/tmp/docker",
                "RAILS_MASTER_KEY=secret",
                "ENCRYPTION_KEY=secret",
                "APP_KEY=secret",
                "CLASSPATH=/tmp/evil.jar",
                "JAVA_OPTIONS=-javaagent:x",
                "MSBUILDSTARTUPHOOKS=/tmp/evil",
                "SOCKS5_SERVER=evil:1080",
                "GIT_SSL_CAPATH=/tmp/evil",
                "DOCKER_CONTEXT=evil",
                "NODE_PATH=/tmp/evil",
                "PHPRC=/tmp/php.ini",
                "MAVEN_OPTS=-javaagent:x",
                "ANSIBLE_SSH_ARGS=-o ProxyJump=evil",
                "ANSIBLE_INVENTORY=/tmp/inv",
                "ANSIBLE_CONFIG=/tmp/ansible.cfg",
                "ANSIBLE_SSH_EXECUTABLE=/tmp/pwn-ssh",
                "VIMINIT=:!id",
                "GRADLE_OPTS=-javaagent:x",
                "SBT_OPTS=-javaagent:x",
                "SVN_SSH=ssh -o ProxyCommand=evil",
                "EXINIT=:!id",
                "RUSTC_WRAPPER=/tmp/pwn",
                "PYTHONBREAKPOINT=os.system",
                "LUA_INIT=@/tmp/evil.lua",
                "CCACHE_PREFIX=/tmp/pwn",
                "SOCKS_SERVER=evil:1080",
                "HELM_KUBEAPISERVER=https://evil",
                "RUSTC=/tmp/pwn-rustc",
                "WINELOADER=/tmp/pwn",
                "MAKEFILES=/tmp/evil.mk",
                "PODMAN_HOST=tcp://evil:2375",
                "HTTPS_PROXY=http://evil",
                "PROMPT_COMMAND=evil",
                "PRIVATE_KEY=pk",
                "SSLKEYLOGFILE=/tmp/ssl.log",
                "GIT_ASKPASS=/tmp/ask",
                "SIYARIX_CONFIG=/tmp/evil.toml",
                "SIYARIX_DATABASE_URL=postgres://u:p@h/db",
                "SIYARIX_REDIS_URL=redis://u:p@h/0",
                "DATABASE_URL=postgres://u:p@h/db",
                "OPENSSL_CONF=/tmp/evil.cnf",
                "LD_AUDIT=/tmp/evil.so",
                "DOCKER_HOST=tcp://evil:2375",
                "KUBECONFIG=/tmp/evil.kube",
                "SIYARIX_CONFIG_DIR=/tmp/evil-cfg",
                "GIT_SSH_COMMAND=ssh -o ProxyCommand=evil",
                "PGPASSFILE=/tmp/pgpass",
                "NETRC=/tmp/netrc",
                "HOME=/tmp/fakehome",
                "SSL_CERT_FILE=/tmp/evil.pem",
                "CURL_CA_BUNDLE=/tmp/evil.pem",
                "REQUESTS_CA_BUNDLE=/tmp/evil.pem",
                "GIT_CONFIG_GLOBAL=/tmp/gitconfig",
                "NPM_CONFIG_REGISTRY=http://evil/npm",
                "DSN=postgres://u:p@h/db",
                "PGSERVICEFILE=/tmp/pg_service",
                "GIT_EXTERNAL_DIFF=evil",
                "GIT_SSL_NO_VERIFY=true",
                "PYTHONHTTPSVERIFY=0",
                "NODE_EXTRA_CA_CERTS=/tmp/evil",
                "GIT_SSL_CAINFO=/tmp/evil",
                "AWS_CA_BUNDLE=/tmp/evil",
                "SSL_CERT_DIR=/tmp/certs",
                "DOCKER_CERT_PATH=/tmp/certs",
                "DOCKER_TLS_VERIFY=0",
                "NODE_TLS_REJECT_UNAUTHORIZED=0",
                "PIP_TRUSTED_HOST=evil.example",
                "NPM_CONFIG_STRICT_SSL=false",
                "COMPOSER_DISABLE_TLS=1",
                "UV_INSECURE_HOST=evil.example",
                "OPENAI_KEY=sk-test",
                "ANTHROPIC_KEY=ak-test",
                "XAI_KEY=xai-test",
                "SIYARIX_OPENAI_KEY=sk-test",
                "GIT_SSH=/tmp/pwn",
                "GIT_PROXY_COMMAND=/tmp/pwn",
                "GIT_CONFIG_KEY_0=core.sshCommand",
                "GIT_CONFIG_VALUE_0=/tmp/pwn",
                "NPM_CONFIG_SCRIPT_SHELL=/tmp/pwn",
                "LESSOPEN=|/tmp/pwn",
                "SUDO_ASKPASS=/tmp/pwn",
                "GCONV_PATH=/tmp",
                "HOSTALIASES=/tmp/hosts",
                "GIT_HTTP_PROXY=http://evil",
                "GIT_HTTPS_PROXY=http://evil",
                "FTP_PROXY=http://evil",
                "SOCKS_PROXY=socks5://evil",
                "KUBE_CONFIG_PATH=/tmp/k",
                "GIT_EXEC_PATH=/tmp/pwn",
                "RSYNC_RSH=ssh -o ProxyCommand=evil",
                "RSYNC_CONNECT_PROG=/tmp/pwn",
                "RSYNC_PROXY=evil:8080",
                "SIYARIX_HARMLESS=ok",
            ]
        ),
        encoding="utf-8",
    )
    for key in (
        "SIYARIX_SAFE_MODE",
        "SIYARIX_PREAUTHORIZED",
        "SIYARIX_COMMAND_REVIEW",
        "SIYARIX_ALLOWED_SCOPE",
        "PERL5OPT",
        "PERLLIB",
        "RUBYOPT",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "JAVA_OPTS",
        "IBM_JAVA_OPTIONS",
        "OPENJ9_JAVA_OPTIONS",
        "CATALINA_OPTS",
        "PERL5DB",
        "SOCKS5_PROXY",
        "OPENSSL_MODULES",
        "OPENSSL_ENGINES",
        "WGETRC",
        "KUBE_CONFIG",
        "DOTNET_STARTUP_HOOKS",
        "DOTNET_AdditionalDeps",
        "CORECLR_PROFILER_PATH",
        "CORECLR_PROFILER_PATH_64",
        "CORECLR_ENABLE_PROFILING",
        "CORECLR_PROFILER",
        "GOCACHEPROG",
        "BASH_FUNC_foo%%",
        "EDITOR",
        "SUDO_EDITOR",
        "ANSIBLE_ACTION_PLUGINS",
        "ANSIBLE_LIBRARY",
        "PYTHONEXECUTABLE",
        "LUA_PATH",
        "BUILDKIT_HOST",
        "RES_OPTIONS",
        "BOTO_CONFIG",
        "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE",
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
        "HTTPS_PROXY",
        "PROMPT_COMMAND",
        "PRIVATE_KEY",
        "SSLKEYLOGFILE",
        "GIT_ASKPASS",
        "SIYARIX_CONFIG",
        "SIYARIX_DATABASE_URL",
        "SIYARIX_REDIS_URL",
        "DATABASE_URL",
        "OPENSSL_CONF",
        "LD_AUDIT",
        "DOCKER_HOST",
        "KUBECONFIG",
        "SIYARIX_CONFIG_DIR",
        "GIT_SSH_COMMAND",
        "PGPASSFILE",
        "NETRC",
        "HOME",
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "GIT_CONFIG_GLOBAL",
        "NPM_CONFIG_REGISTRY",
        "DSN",
        "PGSERVICEFILE",
        "GIT_EXTERNAL_DIFF",
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
        "OPENAI_KEY",
        "ANTHROPIC_KEY",
        "XAI_KEY",
        "SIYARIX_OPENAI_KEY",
        "GIT_SSH",
        "GIT_PROXY_COMMAND",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "NPM_CONFIG_SCRIPT_SHELL",
        "LESSOPEN",
        "SUDO_ASKPASS",
        "GCONV_PATH",
        "HOSTALIASES",
        "GIT_HTTP_PROXY",
        "GIT_HTTPS_PROXY",
        "FTP_PROXY",
        "SOCKS_PROXY",
        "KUBE_CONFIG_PATH",
        "GIT_EXEC_PATH",
        "RSYNC_RSH",
        "RSYNC_CONNECT_PROG",
        "RSYNC_PROXY",
        "SIYARIX_HARMLESS",
    ):
        monkeypatch.delenv(key, raising=False)

    monkeypatch.chdir(tmp_path)
    _load_dotenv(env_file)

    assert "SIYARIX_SAFE_MODE" not in os.environ
    assert "SIYARIX_PREAUTHORIZED" not in os.environ
    assert "SIYARIX_COMMAND_REVIEW" not in os.environ
    assert "SIYARIX_ALLOWED_SCOPE" not in os.environ
    assert "PERL5OPT" not in os.environ
    assert "PERLLIB" not in os.environ
    assert "RUBYOPT" not in os.environ
    assert "JAVA_TOOL_OPTIONS" not in os.environ
    assert "_JAVA_OPTIONS" not in os.environ
    assert "JDK_JAVA_OPTIONS" not in os.environ
    assert "JAVA_OPTS" not in os.environ
    assert "IBM_JAVA_OPTIONS" not in os.environ
    assert "OPENJ9_JAVA_OPTIONS" not in os.environ
    assert "CATALINA_OPTS" not in os.environ
    assert "PERL5DB" not in os.environ
    assert "SOCKS5_PROXY" not in os.environ
    assert "OPENSSL_MODULES" not in os.environ
    assert "OPENSSL_ENGINES" not in os.environ
    assert "WGETRC" not in os.environ
    assert "KUBE_CONFIG" not in os.environ
    assert "DOTNET_STARTUP_HOOKS" not in os.environ
    assert "DOTNET_AdditionalDeps" not in os.environ
    assert "CORECLR_PROFILER_PATH" not in os.environ
    assert "CORECLR_PROFILER_PATH_64" not in os.environ
    assert "CORECLR_ENABLE_PROFILING" not in os.environ
    assert "CORECLR_PROFILER" not in os.environ
    assert "GOCACHEPROG" not in os.environ
    assert "BASH_FUNC_foo%%" not in os.environ
    assert "EDITOR" not in os.environ
    assert "SUDO_EDITOR" not in os.environ
    assert "ANSIBLE_ACTION_PLUGINS" not in os.environ
    assert "ANSIBLE_LIBRARY" not in os.environ
    assert "PYTHONEXECUTABLE" not in os.environ
    assert "LUA_PATH" not in os.environ
    assert "BUILDKIT_HOST" not in os.environ
    assert "RES_OPTIONS" not in os.environ
    assert "BOTO_CONFIG" not in os.environ
    assert "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE" not in os.environ
    assert "HOSTFILE" not in os.environ
    assert "CVS_RSH" not in os.environ
    assert "ZDOTDIR" not in os.environ
    assert "CONTAINER_HOST" not in os.environ
    assert "DOCKER_CONFIG" not in os.environ
    assert "RAILS_MASTER_KEY" not in os.environ
    assert "ENCRYPTION_KEY" not in os.environ
    assert "APP_KEY" not in os.environ
    assert "CLASSPATH" not in os.environ
    assert "JAVA_OPTIONS" not in os.environ
    assert "MSBUILDSTARTUPHOOKS" not in os.environ
    assert "SOCKS5_SERVER" not in os.environ
    assert "GIT_SSL_CAPATH" not in os.environ
    assert "DOCKER_CONTEXT" not in os.environ
    assert "NODE_PATH" not in os.environ
    assert "PHPRC" not in os.environ
    assert "MAVEN_OPTS" not in os.environ
    assert "ANSIBLE_SSH_ARGS" not in os.environ
    assert "ANSIBLE_INVENTORY" not in os.environ
    assert "ANSIBLE_CONFIG" not in os.environ
    assert "ANSIBLE_SSH_EXECUTABLE" not in os.environ
    assert "VIMINIT" not in os.environ
    assert "GRADLE_OPTS" not in os.environ
    assert "SBT_OPTS" not in os.environ
    assert "SVN_SSH" not in os.environ
    assert "EXINIT" not in os.environ
    assert "RUSTC_WRAPPER" not in os.environ
    assert "PYTHONBREAKPOINT" not in os.environ
    assert "LUA_INIT" not in os.environ
    assert "CCACHE_PREFIX" not in os.environ
    assert "SOCKS_SERVER" not in os.environ
    assert "HELM_KUBEAPISERVER" not in os.environ
    assert "RUSTC" not in os.environ
    assert "WINELOADER" not in os.environ
    assert "MAKEFILES" not in os.environ
    assert "PODMAN_HOST" not in os.environ
    assert "HTTPS_PROXY" not in os.environ
    assert "PROMPT_COMMAND" not in os.environ
    assert "PRIVATE_KEY" not in os.environ
    assert "SSLKEYLOGFILE" not in os.environ
    assert "GIT_ASKPASS" not in os.environ
    assert "SIYARIX_CONFIG" not in os.environ
    assert "SIYARIX_DATABASE_URL" not in os.environ
    assert "SIYARIX_REDIS_URL" not in os.environ
    assert "DATABASE_URL" not in os.environ
    assert "OPENSSL_CONF" not in os.environ
    assert "LD_AUDIT" not in os.environ
    assert "DOCKER_HOST" not in os.environ
    assert "KUBECONFIG" not in os.environ
    assert "SIYARIX_CONFIG_DIR" not in os.environ
    assert "GIT_SSH_COMMAND" not in os.environ
    assert "PGPASSFILE" not in os.environ
    assert "NETRC" not in os.environ
    assert "HOME" not in os.environ
    assert "SSL_CERT_FILE" not in os.environ
    assert "CURL_CA_BUNDLE" not in os.environ
    assert "REQUESTS_CA_BUNDLE" not in os.environ
    assert "GIT_CONFIG_GLOBAL" not in os.environ
    assert "NPM_CONFIG_REGISTRY" not in os.environ
    assert "DSN" not in os.environ
    assert "PGSERVICEFILE" not in os.environ
    assert "GIT_EXTERNAL_DIFF" not in os.environ
    assert "GIT_SSL_NO_VERIFY" not in os.environ
    assert "PYTHONHTTPSVERIFY" not in os.environ
    assert "NODE_EXTRA_CA_CERTS" not in os.environ
    assert "GIT_SSL_CAINFO" not in os.environ
    assert "AWS_CA_BUNDLE" not in os.environ
    assert "SSL_CERT_DIR" not in os.environ
    assert "DOCKER_CERT_PATH" not in os.environ
    assert "DOCKER_TLS_VERIFY" not in os.environ
    assert "NODE_TLS_REJECT_UNAUTHORIZED" not in os.environ
    assert "PIP_TRUSTED_HOST" not in os.environ
    assert "NPM_CONFIG_STRICT_SSL" not in os.environ
    assert "COMPOSER_DISABLE_TLS" not in os.environ
    assert "UV_INSECURE_HOST" not in os.environ
    assert "OPENAI_KEY" not in os.environ
    assert "ANTHROPIC_KEY" not in os.environ
    assert "XAI_KEY" not in os.environ
    assert "SIYARIX_OPENAI_KEY" not in os.environ
    assert "GIT_SSH" not in os.environ
    assert "GIT_PROXY_COMMAND" not in os.environ
    assert "GIT_CONFIG_KEY_0" not in os.environ
    assert "GIT_CONFIG_VALUE_0" not in os.environ
    assert "NPM_CONFIG_SCRIPT_SHELL" not in os.environ
    assert "LESSOPEN" not in os.environ
    assert "SUDO_ASKPASS" not in os.environ
    assert "GCONV_PATH" not in os.environ
    assert "HOSTALIASES" not in os.environ
    assert "GIT_HTTP_PROXY" not in os.environ
    assert "GIT_HTTPS_PROXY" not in os.environ
    assert "FTP_PROXY" not in os.environ
    assert "SOCKS_PROXY" not in os.environ
    assert "KUBE_CONFIG_PATH" not in os.environ
    assert "GIT_EXEC_PATH" not in os.environ
    assert "RSYNC_RSH" not in os.environ
    assert "RSYNC_CONNECT_PROG" not in os.environ
    assert "RSYNC_PROXY" not in os.environ
    assert os.environ.get("SIYARIX_HARMLESS") == "ok"
