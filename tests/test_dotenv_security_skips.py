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
                "RUBYOPT=-rfoo",
                "JAVA_TOOL_OPTIONS=-javaagent:x",
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
        "RUBYOPT",
        "JAVA_TOOL_OPTIONS",
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
    assert "RUBYOPT" not in os.environ
    assert "JAVA_TOOL_OPTIONS" not in os.environ
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
    assert os.environ.get("SIYARIX_HARMLESS") == "ok"
