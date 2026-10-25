# SPDX-License-Identifier: AGPL-3.0-or-later
"""Authorized engagement-scope validation for executor commands.

Siyarix is built for security researchers, pentesters, and SOC analysts.
``SIYARIX_ALLOWED_SCOPE`` is an *optional* engagement boundary: when set, every
IP (v4/v6) and domain in a command must fall inside that authorized scope so
automation cannot accidentally pivot outside the engagement. When unset or
empty, this module is a no-op — research tooling (nmap, ssh, mysql, …) runs
unrestricted by scope.

CIDR-only scopes never silently allow domains; there are no hardcoded
public-domain exemptions.
"""

from __future__ import annotations

import ipaddress
import os
import re
import urllib.parse
from typing import Iterable

from .exceptions import PermissionDeniedError

__all__ = [
    "assert_command_in_scope",
    "domain_in_scope",
    "extract_targets",
    "ip_in_scope",
    "parse_allowed_scope",
]

# IPv4 dotted-quad (bounded octets to reduce false positives).
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# Hex / decimal / octal IPv4 obfuscations commonly accepted by curl/wget.
_IPV4_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]{1,8}\b")
_IPV4_DECIMAL_RE = re.compile(r"\b(?:[1-9]\d{7,9}|[1-3]\d{9})\b")  # 8–10 digit ints
# Whole-integer octal IPv4 (e.g. 017700000001 → 127.0.0.1). Leading 0 required.
_IPV4_OCTAL_INT_RE = re.compile(r"\b0[0-7]{8,11}\b")
# Hex-dotted IPv4 with optional mixed decimal octets (0x7f.1, 0x7f.0.0.1).
# Requires at least one ``0x`` octet so plain dotted-decimal is untouched.
_IPV4_HEX_DOTTED_RE = re.compile(
    r"(?<![\w.])(?=(?:[\w.]*0x))"
    r"(?:0x[0-9a-fA-F]{1,2}|\d{1,3})"
    r"(?:\.(?:0x[0-9a-fA-F]{1,2}|\d{1,3})){1,3}(?![\w.])"
)
# Octal-dotted IPv4 (e.g. 0177.0.0.1). Lookahead requires a 0[0-7]+ octet so
# ordinary dotted-decimal (127.0.0.1) is not mis-parsed as base-8.
_IPV4_OCTAL_RE = re.compile(
    r"\b(?=(?:[0-7]{1,4}\.){0,3}0[0-7]+)(?:[0-7]{1,4}\.){3}[0-7]{1,4}\b"
)
# Short IPv4 (curl/wget): 127.1 → 127.0.0.1, 10.1 → 10.0.0.1, 192.168.1 → 192.168.0.1
# Negative lookaround avoids matching a prefix of a full dotted-quad.
_IPV4_SHORT_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){1,2}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"
)
# Short/octal inet_aton forms (0177.1 → 127.0.0.1). Leading-zero octet required.
_IPV4_INET_ATON_RE = re.compile(
    r"(?<![\w.])(?=(?:[\w.]*0[0-7]))"
    r"(?:0x[0-9a-fA-F]{1,2}|0[0-7]{1,3}|[1-9]?\d|1\d{2}|2[0-4]\d|25[0-5]|0)"
    r"(?:\.(?:0x[0-9a-fA-F]{1,2}|0[0-7]{1,3}|[1-9]?\d|1\d{2}|2[0-4]\d|25[0-5]|0)){1,3}"
    r"(?![\w.])"
)

# Bracketed IPv6 literals: https://[2001:db8::1]/80
_IPV6_BRACKETED_RE = re.compile(r"\[([0-9a-fA-F:]+)\]")

# Unbracketed IPv6 candidates (validated via ipaddress).
_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![0-9a-fA-F:])"
)

# Hostnames with a TLD; also match bare "localhost".
_DOMAIN_RE = re.compile(
    r"\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|localhost)\b"
)

# http(s) URLs — used to fail-closed when the host cannot be extracted.
_HTTP_URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
# Schemes that bypass host extraction / are not IP-scoped when scope is set.
_NON_HTTP_URL_RE = re.compile(
    r"\b(?:file|ftp|ftps|gopher|data|unix|smb|nfs|ldap|ldaps|dict|tftp|"
    r"rtsp|ssh|sftp|scp|rsync|git|jar|mailto|telnet):[^\s\"']*",
    re.IGNORECASE,
)
# Host-taking tools + first non-flag single-label hostname (fail-closed under scope).
_HOST_TOOL_NAMES = frozenset(
    {
        "ssh",
        "autossh",
        "nmap",
        "ncat",
        "nc",
        "netcat",
        "ping",
        "traceroute",
        "tracepath",
        "dig",
        "host",
        "telnet",
        "ldapsearch",
        "smbclient",
        "rpcclient",
        "showmount",
        "masscan",
        "naabu",
        "httpx",
        "curl",
        "wget",
        "ftp",
        "scp",
        "sftp",
        "rsync",
        "lftp",
        "aria2c",
        "enum4linux",
        "enum4linux-ng",
        "impacket-smbclient",
        "socat",
        "openssl",
        "git",
        "mysql",
        "psql",
        "redis-cli",
        "mongosh",
        "mongo",
        "impacket-psexec",
        "psexec.py",
        "evil-winrm",
        "xfreerdp",
        "docker",
        "podman",
        "kubectl",
        "oc",
        "helm",
        "kustomize",
        "nerdctl",
        "clickhouse-client",
        "clickhouse",
        "cqlsh",
        "nslookup",
        "ansible",
        "ansible-playbook",
        "ansible-inventory",
        "sshuttle",
        "chisel",
        "crackmapexec",
        "cme",
        "nxc",
        "netexec",
        "nikto",
        "hydra",
        "medusa",
        "ncrack",
        "patator",
        "ligolo-ng",
        "ligolo",
        "rdesktop",
        "freerdp",
        "impacket-wmiexec",
        "wmiexec.py",
        "impacket-smbexec",
        "smbexec.py",
        "impacket-atexec",
        "atexec.py",
        "sqlcmd",
        "mssql-cli",
        "osql",
        "smbmap",
        # Proxy / tunnel wrappers — engagement-bound when scope is set (RH-06/16).
        "proxychains",
        "proxychains4",
        "torsocks",
        "torify",
        "tsocks",
        "gost",
        "ss-local",
        "ss-server",
        "ss-redir",
        "ss-tunnel",
        "shadowsocks",
        "shadowsocks-libev",
        "shadowsocks-client",
        "v2ray",
        "xray",
        "corkscrew",
        "connect-proxy",
        "connect",
        "pproxy",
        "proxy.py",
        "redsocks",
        "microsocks",
        "brook",
        "mitmproxy",
        "mitmdump",
        "mitmweb",
        "cloudflared",
        "ngrok",
        "bore",
        "localtunnel",
        "lt",
        # Image / local-cluster pivots (RH-42).
        "skopeo",
        "buildah",
        "minikube",
        "kind",
        "istioctl",
        "telepresence",
        # VPN / mesh / covert tunnels (RH-44).
        "wg-quick",
        "wireguard",
        "wg",
        "openvpn",
        "openconnect",
        "tailscale",
        "frpc",
        "frps",
        "clash",
        "clash-meta",
        "mihomo",
        "sing-box",
        "hysteria",
        "hysteria2",
        "trojan",
        "wstunnel",
        "dnscat2",
        "iodine",
        "pingtunnel",
        "udp2raw",
        "kcptun-client",
        "kcptun-server",
        "sshx",
        "softether-vpnclient",
        "vpncloud",
        # Mesh / overlay VPN clients (RH-45).
        "zerotier-cli",
        "zerotier-one",
        "netbird",
        "headscale",
        "innernet",
        "firezone",
        "nebula",
        "v2raya",
        "proxifier",
        "outline-ss-server",
        "outline-client",
        # RH-46 — IPsec / local-cluster / short proxies / FUSE tunnels.
        "ipsec",
        "strongswan",
        "strongswan-starter",
        "vpnc",
        "lima",
        "colima",
        "lxd",
        "incus",
        "singularity",
        "apptainer",
        "privoxy",
        "polipo",
        "tinyproxy",
        "dante",
        "danted",
        "icmptunnel",
        "stunnel",
        "stunnel4",
        "rathole",
        # RH-47 — SOCKS daemons, Tor/I2P, VPN activate, local k8s.
        "sockd",
        "ss5",
        "cntlm",
        "srelay",
        "delegate",
        "tor",
        "obfs4proxy",
        "lyrebird",
        "snowflake-client",
        "meek-client",
        "i2pd",
        "onioncat",
        "openfortivpn",
        "twingate",
        "cloudflare-warp",
        "warp-cli",
        "tincd",
        "tinc",
        "forticlient",
        "hamachi",
        "k3d",
        "k3s",
        "kubefwd",
        "microk8s",
    }
)
# When scope is set, these tools create out-of-engagement pivots / public ingress.
_SCOPE_BLOCKED_WRAPPERS: frozenset[str] = frozenset(
    {
        "proxychains",
        "proxychains4",
        "torsocks",
        "torify",
        "tsocks",  # RH-16
        "gost",  # RH-20
        "ss-local",
        "ss-server",
        "ss-redir",
        "ss-tunnel",
        "shadowsocks",
        "shadowsocks-libev",
        "shadowsocks-client",
        "v2ray",
        "xray",
        "corkscrew",  # RH-25
        "connect-proxy",
        "connect",
        "pproxy",  # RH-32
        "proxy.py",
        "redsocks",  # RH-37
        "microsocks",
        "brook",  # RH-43
        "mitmproxy",
        "mitmdump",
        "mitmweb",
        "cloudflared",
        "ngrok",
        "bore",
        "localtunnel",
        "lt",
        # Local-cluster / mesh sidecars hide API egress (RH-42).
        "minikube",
        "kind",
        "istioctl",
        "telepresence",
        # VPN / mesh / covert tunnels (RH-44).
        "wg-quick",
        "wireguard",
        "wg",
        "openvpn",
        "openconnect",
        "tailscale",
        "frpc",
        "frps",
        "clash",
        "clash-meta",
        "mihomo",
        "sing-box",
        "hysteria",
        "hysteria2",
        "trojan",
        "wstunnel",
        "dnscat2",
        "iodine",
        "pingtunnel",
        "udp2raw",
        "kcptun-client",
        "kcptun-server",
        "sshx",
        "softether-vpnclient",
        "vpncloud",
        # Mesh / overlay VPN clients (RH-45).
        "zerotier-cli",
        "zerotier-one",
        "netbird",
        "headscale",
        "innernet",
        "firezone",
        "nebula",
        "v2raya",
        "proxifier",
        "outline-ss-server",
        "outline-client",
        # RH-46 — IPsec / local-cluster / short proxies / FUSE tunnels.
        "ipsec",
        "strongswan",
        "strongswan-starter",
        "vpnc",
        "lima",
        "colima",
        "lxd",
        "incus",
        "singularity",
        "apptainer",
        "privoxy",
        "polipo",
        "tinyproxy",
        "dante",
        "danted",
        "icmptunnel",
        "stunnel",
        "stunnel4",
        "rathole",
        # RH-47 — SOCKS daemons, Tor/I2P, VPN activate, local k8s.
        "sockd",
        "ss5",
        "cntlm",
        "srelay",
        "delegate",
        "tor",
        "obfs4proxy",
        "lyrebird",
        "snowflake-client",
        "meek-client",
        "i2pd",
        "onioncat",
        "openfortivpn",
        "twingate",
        "cloudflare-warp",
        "warp-cli",
        "tincd",
        "tinc",
        "forticlient",
        "hamachi",
        "k3d",
        "k3s",
        "kubefwd",
        "microk8s",
    }
)
# Glued short host flags: ``mysql -h1.1.1.1``, ``evil-winrm -i10.0.0.1``, ``sqlcmd -S1.1.1.1``.
_GLUED_HOST_SHORT_RE = re.compile(
    r"^(?P<flag>-[hHiS])(?P<val>[^=\s-].+)$"
)
# Glued long host/connect flags: ``openssl … -connect1.1.1.1:443``.
_GLUED_HOST_LONG_RE = re.compile(
    r"^(?P<flag>--host|--ip|--server|--proxy|-host|-connect|-proxy)"
    r"(?:=(?P<eq>.+)|(?P<glued>[^=].+))$",
    re.IGNORECASE,
)
# hydra/medusa trailing service tokens (not hosts).
_BRUTE_SERVICE_TOKENS = frozenset(
    {
        "ssh",
        "ftp",
        "ftps",
        "http",
        "https",
        "http-get",
        "http-post",
        "http-head",
        "http-form-get",
        "http-form-post",
        "smb",
        "smb2",
        "rdp",
        "vnc",
        "mysql",
        "mssql",
        "postgres",
        "postgresql",
        "redis",
        "mongodb",
        "ldap",
        "ldaps",
        "telnet",
        "sftp",
        "imap",
        "imaps",
        "pop3",
        "pop3s",
        "smtp",
        "smtps",
        "snmp",
        "cisco",
        "cisco-enable",
        "rsh",
        "rexec",
        "nntp",
        "pcanywhere",
        "teamspeak",
        "xmpp",
        "irc",
        "svn",
        "git",
        "winrm",
        "winrms",
    }
)
# socat address forms: ``TCP:host:port``, ``OPENSSL:host:port``, …
_SOCAT_ADDR_RE = re.compile(
    r"(?i)^(?:TCP(?:[46])?|UDP(?:[46])?|OPENSSL|SSL):"
    r"(?:\[(?P<v6>[^\]]+)\]|(?P<host>[^:]+))(?::\d+)?$"
)
# socat SOCKS/PROXY: ``SOCKS4A:proxy:dest:port`` — check proxy AND dest.
_SOCAT_SOCKS_RE = re.compile(
    r"(?i)^(?:SOCKS4A?|PROXY):"
    r"(?P<proxy>[^:]+):(?:\[(?P<v6>[^\]]+)\]|(?P<host>[^:]+))(?::\d+)?$"
)
# Glued ssh ``-oProxyJump=evil`` / ``-oProxyCommand=…`` / ``-oDynamicForward=…`` /
# ``-oTunnel=ethernet`` (RH-19).
_GLUED_SSH_O_RE = re.compile(
    r"(?i)^(?:-o|--option)['\"]?"
    r"(?P<key>proxyjump|proxycommand|dynamicforward|localforward|remoteforward|tunnel)"
    r"=(?P<val>.+?)['\"]?$"
)
# Leading ``ALL_PROXY=… curl …`` style env assignments (SOCKS/HTTP pivots).
_SCOPE_PROXY_ENV_NAMES: frozenset[str] = frozenset(
    {
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "FTP_PROXY",
        "SOCKS_PROXY",
        "SOCKS5_PROXY",
        "SOCKS5_SERVER",
        "SOCKS_SERVER",
        "GIT_HTTP_PROXY",
        "GIT_HTTPS_PROXY",
        "RSYNC_PROXY",
        "GRPC_PROXY",
        "grpc_proxy",
        # Client HTTP library proxy pivots (RH-46).
        "HTTPX_PROXY",
        "REQUESTS_PROXY",
        "AIOHTTP_PROXY",
        "TOR_SOCKS_HOST",
        "TOR_SOCKS_PORT",
    }
)
# Leading daemon / transport pivots that hide the real egress host (RH-14/15).
_SCOPE_TRANSPORT_ENV_NAMES: frozenset[str] = frozenset(
    {
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "CONTAINER_HOST",
        "PODMAN_HOST",
        "PODMAN_CONNECTION",
        "BUILDKIT_HOST",
        "CONTAINERS_CONF",
        "CRICTL_RUNTIME_ENDPOINT",
        "GIT_SSH_COMMAND",
        "GIT_SSH",
        "GIT_PROXY_COMMAND",
        "RSYNC_RSH",
        "RSYNC_CONNECT_PROG",
        "CVS_RSH",
        "SVN_SSH",
        "ANSIBLE_SSH_EXECUTABLE",
        "ANSIBLE_SSH_ARGS",
        "KUBECONFIG",
        "KUBE_CONFIG",
        "KUBE_CONFIG_PATH",
        "HELM_KUBECONFIG",
        "KUBERNETES_SERVICE_HOST",
        "KUBERNETES_SERVICE_PORT",
        # DB client transport hosts (RH-24 / RH-46).
        "MYSQL_HOST",
        "MYSQLHOST",
        "MYSQL_UNIX_PORT",
        "PGHOST",
        "PGHOSTADDR",
        "PGPORT",
        "PGSERVICE",
        "PGSERVICEFILE",
        "REDIS_HOST",
        "REDIS_URL",
        "MONGO_URL",
        "MONGODB_URI",
        "DATABASE_URL",
        "DATABASE_HOST",
        "DB_HOST",
        "SQLALCHEMY_DATABASE_URI",
        "AZURE_MYSQL_HOST",
        # Service discovery / DB hosts (RH-33).
        "CONSUL_HTTP_ADDR",
        "CONSUL_HTTP_HOST",
        "VAULT_ADDR",
        "NOMAD_ADDR",
        "CLICKHOUSE_HOST",
        "CASSANDRA_HOST",
        "ETCDCTL_ENDPOINTS",
        # Cloud object-store endpoint pivots (RH-46).
        "AWS_ENDPOINT",
        "AWS_ENDPOINT_URL",
        "S3_ENDPOINT",
        "MINIO_ENDPOINT",
        "NERDCTL_HOST",
        "MSSQL_HOST",
        "DYNAMODB_ENDPOINT",
        "R2_ENDPOINT",
        "ELASTICSEARCH_HOST",
        "KAFKA_HOST",
        "BOUNDARY_ADDR",
        "TORSOCKS_TOR_ADDRESS",
    }
)
# Cloud CLIs that rewrite kubeconfig to an opaque API server (RH-46).
_CLOUD_KUBECONFIG_TOOLS: frozenset[str] = frozenset(
    {
        "aws",
        "gcloud",
        "az",
        "eksctl",
        "doctl",
        "oci",
        "talosctl",
        "k0s",
        "microk8s",
    }
)
_CLOUD_KUBECONFIG_VERBS: frozenset[str] = frozenset(
    {
        "update-kubeconfig",
        "get-credentials",
        "write-kubeconfig",
        "create-kubeconfig",
        "kubeconfig",
    }
)
# Glued short proxy/jump: ``-x11.1.1.1:8080``, ``-Jbastion``.
_GLUED_PROXY_SHORT_RE = re.compile(
    r"^(?P<flag>-[xJ])(?P<val>.+)$"
)
_SHELL_WRAPPERS = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"}
)
# ``bash -c '…'``, ``su user -c '…'``, ``sudo -c '…'``, ``script -c '…'``.
_SHELL_C_PAYLOAD_RE = re.compile(
    r"(?i)(?:^|\s)(?:(?:[\w./-]*/)?(?:(?:ba|da|z|k)?sh|ash|su|sudo|script))\b"
    r"[\s\S]{0,80}?(?:--command=|-c)\s+(?:'([^']*)'|\"([^\"]*)\"|(\S+))"
)
# UNC hosts: ``//evil-host/share`` (callers normalize ``\\`` → ``/`` first).
# Negative lookbehind skips URL schemes (``https://host/...``).
_UNC_HOST_RE = re.compile(r"(?<!:)//([^/\s]+)(?:/|\s|$)")
# scp/sftp remote: ``[user@]host:path`` (local paths have no ``host:`` form).
_SCP_REMOTE_RE = re.compile(
    r"^(?:(?P<user>[^@/\s]+)@)?(?P<host>\[[^\]]+\]|[^@/\s:]+):(?P<path>.*)$"
)
_SINGLE_LABEL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,62}$")

# Scope entry that is purely an IP or CIDR (not a domain / wildcard).
_IP_OR_CIDR_RE = re.compile(
    r"^(?:"
    r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?"  # IPv4 / CIDR
    r"|[0-9a-fA-F:]+(?:/\d{1,3})?"  # IPv6 / CIDR
    r")$"
)


def parse_allowed_scope(scope_env: str | None = None) -> list[str]:
    """Parse ``SIYARIX_ALLOWED_SCOPE`` (comma-separated) into normalized items."""
    raw = scope_env if scope_env is not None else os.environ.get("SIYARIX_ALLOWED_SCOPE", "")
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def _decode_for_extract(command: str) -> str:
    """URL-decode percent-escapes (and a second pass) so ``evil%2ecom`` is visible."""
    text = command or ""
    for _ in range(2):
        try:
            decoded = urllib.parse.unquote(text)
        except Exception:
            break
        if decoded == text:
            break
        text = decoded
    return text


def _try_int_ip(token: str) -> str | None:
    """Parse hex/decimal/octal integer forms of IPv4.

    Examples: ``0x7f000001``, ``2130706433``, ``017700000001``.
    """
    try:
        lower = token.lower()
        if lower.startswith("0x"):
            value = int(token, 16)
        elif token.startswith("0") and len(token) > 1 and all(
            c in "01234567" for c in token
        ):
            value = int(token, 8)
        elif token.isdigit():
            value = int(token, 10)
        else:
            return None
        if not 0 <= value <= 0xFFFFFFFF:
            return None
        return str(ipaddress.IPv4Address(value))
    except (ValueError, OverflowError):
        return None


def _parse_inet_octet(part: str) -> int | None:
    """Parse one IPv4 octet (decimal, leading-zero octal, or ``0x`` hex)."""
    try:
        lower = part.lower()
        if lower.startswith("0x"):
            value = int(part, 16)
        elif part.startswith("0") and len(part) > 1 and all(c in "01234567" for c in part):
            value = int(part, 8)
        elif part.isdigit():
            value = int(part, 10)
        else:
            return None
        if 0 <= value <= 255:
            return value
    except ValueError:
        return None
    return None


def _expand_hex_dotted_ipv4(token: str) -> str | None:
    """Expand hex-dotted IPv4 (``0x7f.1``, ``0x7f.0.0.1``) like inet_aton.

    Requires at least one ``0x`` octet so plain dotted forms are not mis-parsed.
    """
    parts = token.split(".")
    if not (2 <= len(parts) <= 4):
        return None
    if not any(p.lower().startswith("0x") for p in parts):
        return None
    nums: list[int] = []
    for part in parts:
        n = _parse_inet_octet(part)
        if n is None:
            return None
        nums.append(n)
    if len(nums) == 2:
        dotted = f"{nums[0]}.0.0.{nums[1]}"
    elif len(nums) == 3:
        dotted = f"{nums[0]}.{nums[1]}.0.{nums[2]}"
    else:
        dotted = ".".join(str(n) for n in nums)
    try:
        return str(ipaddress.IPv4Address(dotted))
    except ValueError:
        return None


def _expand_inet_aton_ipv4(token: str) -> str | None:
    """Expand short/octal IPv4 the way curl/glibc ``inet_aton`` does (``0177.1``)."""
    parts = token.split(".")
    if not (2 <= len(parts) <= 4):
        return None
    # Require a leading-zero octal octet so plain ``127.1`` still uses short-decimal.
    if not any(
        p.startswith("0") and len(p) > 1 and all(c in "01234567" for c in p) for p in parts
    ):
        return None
    nums: list[int] = []
    for part in parts:
        n = _parse_inet_octet(part)
        if n is None:
            return None
        nums.append(n)
    if len(nums) == 2:
        dotted = f"{nums[0]}.0.0.{nums[1]}"
    elif len(nums) == 3:
        dotted = f"{nums[0]}.{nums[1]}.0.{nums[2]}"
    else:
        dotted = ".".join(str(n) for n in nums)
    try:
        return str(ipaddress.IPv4Address(dotted))
    except ValueError:
        return None


def _expand_short_ipv4(token: str) -> str | None:
    """Expand curl-style short IPv4 (``127.1``, ``10.0.1``) to dotted-quad."""
    parts = token.split(".")
    if len(parts) not in (2, 3):
        return None
    try:
        nums = [int(p, 10) for p in parts]
    except ValueError:
        return None
    if any(n < 0 or n > 255 for n in nums):
        return None
    if len(nums) == 2:
        dotted = f"{nums[0]}.0.0.{nums[1]}"
    else:
        dotted = f"{nums[0]}.{nums[1]}.0.{nums[2]}"
    try:
        return str(ipaddress.IPv4Address(dotted))
    except ValueError:
        return None


def extract_targets(command: str) -> tuple[list[str], list[str]]:
    """Extract IP addresses and domain names referenced in *command*.

    Returns ``(ips, domains)`` with lowercase domains and string IP forms.
    IPv6 addresses are recognized in both bracketed and bare form.
    Percent-encoded hosts and hex/decimal/octal IPv4 obfuscations are decoded.
    """
    text = _decode_for_extract(command)
    ips: list[str] = []
    seen_ips: set[str] = set()

    def _add_ip(candidate: str) -> None:
        try:
            normalized = str(ipaddress.ip_address(candidate))
        except ValueError:
            return
        if normalized not in seen_ips:
            seen_ips.add(normalized)
            ips.append(normalized)

    for match in _IPV4_RE.findall(text):
        _add_ip(match)

    # Expand hex-dotted first and scrub so short/int parsers do not see
    # embedded ``0.0`` fragments inside ``0x7f.0x0.0x0.0x1``.
    scrubbed_ipv4 = text
    for match in _IPV4_HEX_DOTTED_RE.findall(text):
        expanded = _expand_hex_dotted_ipv4(match)
        if expanded:
            _add_ip(expanded)
        scrubbed_ipv4 = scrubbed_ipv4.replace(match, " ")

    for match in _IPV4_SHORT_RE.findall(scrubbed_ipv4):
        # Skip full dotted-quad already handled by _IPV4_RE.
        if match.count(".") == 3:
            continue
        expanded = _expand_short_ipv4(match)
        if expanded:
            _add_ip(expanded)

    for match in _IPV4_INET_ATON_RE.findall(scrubbed_ipv4):
        expanded = _expand_inet_aton_ipv4(match)
        if expanded:
            _add_ip(expanded)

    for match in _IPV4_OCTAL_RE.findall(scrubbed_ipv4):
        # Convert octal-dotted form (0177.0.0.1) via int(..., 8) per octet.
        try:
            parts = [str(int(p, 8)) for p in match.split(".")]
            _add_ip(".".join(parts))
        except ValueError:
            continue

    for match in _IPV4_HEX_RE.findall(scrubbed_ipv4):
        parsed = _try_int_ip(match)
        if parsed:
            _add_ip(parsed)

    for match in _IPV4_OCTAL_INT_RE.findall(scrubbed_ipv4):
        parsed = _try_int_ip(match)
        if parsed:
            _add_ip(parsed)

    for match in _IPV4_DECIMAL_RE.findall(scrubbed_ipv4):
        parsed = _try_int_ip(match)
        if parsed:
            _add_ip(parsed)

    for match in _IPV6_BRACKETED_RE.findall(text):
        _add_ip(match)

    # Strip bracketed spans so bare IPv6 scan does not re-parse them oddly.
    scrubbed = _IPV6_BRACKETED_RE.sub(" ", text)
    # Avoid treating IPv4 as IPv6 candidates.
    scrubbed = _IPV4_RE.sub(" ", scrubbed)
    for match in _IPV6_CANDIDATE_RE.findall(scrubbed):
        _add_ip(match)

    domains: list[str] = []
    seen_domains: set[str] = set()
    for match in _DOMAIN_RE.findall(text):
        domain = match.lower()
        # Skip tokens that are valid IPs (e.g. odd parses).
        try:
            ipaddress.ip_address(domain)
            continue
        except ValueError:
            pass
        if domain not in seen_domains:
            seen_domains.add(domain)
            domains.append(domain)

    return ips, domains


def ip_in_scope(ip_str: str, allowed_items: Iterable[str]) -> bool:
    """Return True if *ip_str* is covered by an exact IP or CIDR in *allowed_items*."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for allowed in allowed_items:
        if "/" in allowed:
            try:
                net = ipaddress.ip_network(allowed, strict=False)
            except ValueError:
                continue
            if ip in net:
                return True
        else:
            try:
                if ip == ipaddress.ip_address(allowed):
                    return True
            except ValueError:
                continue
    return False


def domain_in_scope(domain: str, allowed_items: Iterable[str]) -> bool:
    """Return True only when *domain* matches an explicit domain scope entry.

    CIDR / IP-only scope entries never authorize a domain (fail-closed; no
    silent expansion via DNS or public allow-lists).
    """
    domain = domain.lower().rstrip(".")
    for allowed in allowed_items:
        if _IP_OR_CIDR_RE.match(allowed):
            continue
        if allowed.startswith("*."):
            suffix = allowed[1:]  # ".example.com"
            if domain.endswith(suffix) or domain == allowed[2:]:
                return True
        elif domain == allowed:
            return True
    return False


def _assert_host_token_in_scope(
    candidate: str, allowed_items: Iterable[str], scope_display: str
) -> None:
    """Fail-closed for a single host/IP token under authorized scope."""
    host = (candidate or "").strip().strip("[]").lower().rstrip(".")
    if not host:
        return
    int_ip = _try_int_ip(host)
    if int_ip is not None:
        if not ip_in_scope(int_ip, allowed_items):
            raise PermissionDeniedError(
                f"Target IP {int_ip} is out of authorized scope: {scope_display}"
            )
        return
    try:
        ip = str(ipaddress.ip_address(host))
    except ValueError:
        if (
            _SINGLE_LABEL_RE.match(host)
            or "." in host
            or host == "localhost"
        ) and not domain_in_scope(host, allowed_items):
            raise PermissionDeniedError(
                f"Target host {host} is out of authorized scope: {scope_display}"
            )
    else:
        if not ip_in_scope(ip, allowed_items):
            raise PermissionDeniedError(
                f"Target IP {ip} is out of authorized scope: {scope_display}"
            )


def _glued_host_flag_value(
    token: str, *, short: frozenset[str], long: frozenset[str]
) -> str | None:
    """Return host value from glued ``-h1.1.1.1`` / ``-connecthost:443`` forms."""
    raw = (token or "").strip().strip("'\"")
    if not raw.startswith("-"):
        return None
    # Prefer long flags so ``-host=evil`` is not parsed as ``-h`` + ``ost=evil``.
    long_m = _GLUED_HOST_LONG_RE.match(raw)
    if long_m is not None and long_m.group("flag").lower() in {f.lower() for f in long}:
        return (long_m.group("eq") or long_m.group("glued") or "").strip().strip("'\"")
    short_m = _GLUED_HOST_SHORT_RE.match(raw)
    if short_m is not None and short_m.group("flag") in short:
        return short_m.group("val").strip().strip("'\"")
    return None



# Strip Go/release platform + version suffixes: ``gost-linux-amd64``, ``ngrok-v3`` (RH-47).
_TOOL_PLATFORM_SUFFIX_RE = re.compile(
    r"-(?:linux|darwin|windows|freebsd|openbsd|netbsd|macos)"
    r"(?:-(?:amd64|arm64|armv\d+|arm|386|x86_64|aarch64|ppc64le|s390x|riscv64|musl))?$",
    re.IGNORECASE,
)
_TOOL_VERSION_SUFFIX_RE = re.compile(r"-v?\d+(?:\.\d+)*$", re.IGNORECASE)


def _normalize_tool_basename(name: str) -> str:
    """Return canonical tool basename after stripping path and release suffixes."""
    base = name.lstrip("\\").rstrip("/").rsplit("/", 1)[-1].lower()
    changed = True
    while changed:
        changed = False
        nxt = _TOOL_PLATFORM_SUFFIX_RE.sub("", base)
        if nxt != base:
            base, changed = nxt, True
            continue
        nxt = _TOOL_VERSION_SUFFIX_RE.sub("", base)
        if nxt != base:
            base, changed = nxt, True
    return base


def assert_command_in_scope(command: str, scope_env: str | None = None) -> None:
    """Raise :class:`PermissionDeniedError` if any target is outside authorized scope.

    When scope is unset or empty, this is a no-op (caller decides policy).
    Fail-closed for ``http(s)://`` URLs whose host cannot be extracted/parsed
    when a scope is configured (blocks obfuscated host bypasses).
    """
    allowed_items = parse_allowed_scope(scope_env)
    if not allowed_items:
        return

    scope_display = (
        scope_env if scope_env is not None else os.environ.get("SIYARIX_ALLOWED_SCOPE", "")
    )
    found_ips, found_domains = extract_targets(command)

    decoded_early = _decode_for_extract(command)
    # Fail-closed: leading ``ALL_PROXY=…`` / ``DOCKER_HOST=…`` / ``GIT_SSH_COMMAND=…``
    # pivots that hide real egress (RH-10 / RH-14 / RH-15).
    for tok in decoded_early.split():
        if "=" not in tok or tok.startswith("-"):
            continue
        key, sep, _val = tok.partition("=")
        if not sep or not key:
            continue
        key_u = key.upper()
        if key_u in _SCOPE_PROXY_ENV_NAMES or key_u.endswith("_PROXY"):
            raise PermissionDeniedError(
                f"Proxy environment assignment {key}= is not allowed under authorized "
                f"scope (authorized scope: {scope_display})"
            )
        if key_u in _SCOPE_TRANSPORT_ENV_NAMES:
            raise PermissionDeniedError(
                f"Transport environment assignment {key}= is not allowed under "
                f"authorized scope (authorized scope: {scope_display})"
            )
    # Fail-closed: SOCKS/proxy wrappers and public tunnels hide real egress (RH-06).
    for tok in decoded_early.split():
        if "=" in tok and not tok.startswith("-"):
            # ``ALL_PROXY=…`` is not a tool name.
            continue
        base = _normalize_tool_basename(tok)
        if base in _SCOPE_BLOCKED_WRAPPERS:
            raise PermissionDeniedError(
                f"Proxy/tunnel tool {base!r} is not allowed under authorized scope "
                f"(authorized scope: {scope_display})"
            )
    # RH-44: ``rclone mount`` remotes are opaque egress pivots under engagement scope.
    if re.search(r"\brclone\b", decoded_early, re.IGNORECASE) and re.search(
        r"(?:^|\s)mount(?:\s|$)", decoded_early, re.IGNORECASE
    ):
        raise PermissionDeniedError(
            f"rclone mount is not allowed under authorized scope "
            f"(authorized scope: {scope_display})"
        )
    # RH-45: ``ip tuntap`` / ``ip tunnel`` create out-of-engagement L3 pivots.
    if re.search(r"\bip\b", decoded_early, re.IGNORECASE) and re.search(
        r"(?:^|\s)(?:tuntap|tunnel)(?:\s|$)", decoded_early, re.IGNORECASE
    ):
        raise PermissionDeniedError(
            f"ip tuntap/tunnel is not allowed under authorized scope "
            f"(authorized scope: {scope_display})"
        )
    # RH-47: NetworkManager VPN activate (opaque peer in connection profile).
    if re.search(r"\bnmcli\b", decoded_early, re.IGNORECASE) and re.search(
        r"\bconnection\b[\s\S]{0,40}\bup\b", decoded_early, re.IGNORECASE
    ):
        raise PermissionDeniedError(
            f"nmcli connection up is not allowed under authorized scope "
            f"(authorized scope: {scope_display})"
        )
    # RH-46/47: cloud CLIs rewriting kubeconfig (not in _HOST_TOOL_NAMES).
    _early_tokens = decoded_early.split()
    if _early_tokens:
        _early_base = _normalize_tool_basename(_early_tokens[0])
        _rest = [t.lower().strip().strip("'\"") for t in _early_tokens[1:]]
        if _early_base in _CLOUD_KUBECONFIG_TOOLS:
            for j, low in enumerate(_rest):
                if low in _CLOUD_KUBECONFIG_VERBS or low == "create-kubeconfig":
                    raise PermissionDeniedError(
                        f"{_early_base} kubeconfig rewrite ({low}) is not allowed under "
                        f"authorized scope (authorized scope: {scope_display}); "
                        f"pass an explicit in-scope --server / API host instead"
                    )
                # ``microk8s config`` dumps/writes kubeconfig (RH-47).
                if _early_base == "microk8s" and low == "config":
                    raise PermissionDeniedError(
                        f"microk8s config is not allowed under authorized scope "
                        f"(authorized scope: {scope_display})"
                    )
        # RH-47: opaque AWS SSM / ECS interactive shells.
        if _early_base == "aws":
            if "start-session" in _rest or "execute-command" in _rest:
                raise PermissionDeniedError(
                    f"aws SSM/ECS interactive session is not allowed under "
                    f"authorized scope (authorized scope: {scope_display})"
                )
    # Fail-closed: ``psql service=…`` hides the remote host in a service file.
    if re.search(r"\bpsql\b", decoded_early, re.IGNORECASE) and re.search(
        r"(?:\bservice\s*=|--service(?:=|\s))\s*\S+",
        decoded_early,
        re.IGNORECASE,
    ):
        raise PermissionDeniedError(
            f"psql service= targets are not allowed under authorized scope "
            f"(authorized scope: {scope_display}); pass an explicit -h/--host instead"
        )
    # Unwrap ``bash -c 'nmap evil'`` / ``sh -c "ssh bastion"`` — re-check payload.
    _shell_c = _SHELL_C_PAYLOAD_RE.search(decoded_early)
    if _shell_c:
        payload = next((g for g in _shell_c.groups() if g), "")
        if payload.strip():
            assert_command_in_scope(payload.strip(), scope_env=scope_env)

    for url in _NON_HTTP_URL_RE.findall(decoded_early):
        raise PermissionDeniedError(
            f"URL scheme not allowed under authorized scope: {url!r} "
            f"(authorized scope: {scope_display})"
        )

    # Fail-closed: UNC hosts in any tool (``mount -t cifs //evil/share``, smbclient).
    for unc_host in _UNC_HOST_RE.findall(decoded_early.replace("\\", "/")):
        # After backslash→slash normalize, pattern still sees ``//host/``.
        host = unc_host.strip().lower().rstrip(".")
        if not host:
            continue
        int_ip = _try_int_ip(host)
        if int_ip is not None:
            if not ip_in_scope(int_ip, allowed_items):
                raise PermissionDeniedError(
                    f"Target IP {int_ip} is out of authorized scope: {scope_display}"
                )
            continue
        try:
            ip = str(ipaddress.ip_address(host))
        except ValueError:
            if not domain_in_scope(host, allowed_items):
                raise PermissionDeniedError(
                    f"Target host {host} is out of authorized scope: {scope_display}"
                )
        else:
            if not ip_in_scope(ip, allowed_items):
                raise PermissionDeniedError(
                    f"Target IP {ip} is out of authorized scope: {scope_display}"
                )

    # Fail-closed: bare hosts after host-taking tools (``ssh bastion``, ``curl 0``).
    _port_flags = frozenset({"-p", "-P", "--port", "--ports"})
    tokens = decoded_early.split()
    if tokens:
        argv0 = tokens[0].lstrip("\\")
        if argv0.startswith("`") or "$(" in argv0 or argv0.startswith("${"):
            raise PermissionDeniedError(
                f"Command-substitution argv0 is not allowed under authorized scope "
                f"(authorized scope: {scope_display})"
            )
    for i, tok in enumerate(tokens):
        # Basename path-qualified tools: ``/usr/bin/curl``, ``./curl``, ``\curl``.
        base = _normalize_tool_basename(tok)
        if base not in _HOST_TOOL_NAMES:
            continue
        # Fail-closed: URL-from-file / curl config hides the real target.
        # (curl ``-i`` is Include headers — only wget uses ``-i`` as input-file.)
        for nxt in tokens[i + 1 :]:
            flag = nxt.split("=", 1)[0]
            curl_cfg = base in {"curl", "http", "httpie"} and (
                flag in {"-K", "--config"}
                or flag.startswith("--config")
                or flag.startswith("-K")
            )
            wget_cfg = base == "wget" and (
                flag in {"-i", "--input-file", "--config"}
                or flag.startswith("--input-file")
                or flag.startswith("--config")
                or re.match(r"^-i/", flag) is not None
            )
            aria_in = base == "aria2c" and (
                flag in {"-i", "--input-file"}
                or flag.startswith("--input-file")
                or re.match(r"^-i/", flag) is not None
            )
            # Opaque kube API endpoint via config file (RH-21 / RH-26).
            kube_cfg = base in {"kubectl", "oc", "helm", "kustomize"} and (
                flag in {"--kubeconfig", "--kube-config"}
                or flag.startswith("--kubeconfig")
                or flag.startswith("--kube-config")
            )
            # nerdctl/docker-compatible remote host (RH-26).
            nerd_host = base == "nerdctl" and (
                flag in {"--host", "-H", "--address"}
                or flag.startswith("--host")
                or flag.startswith("-H")
            )
            if curl_cfg or wget_cfg or aria_in or kube_cfg or nerd_host:
                raise PermissionDeniedError(
                    f"URL/config-from-file is not allowed under authorized scope "
                    f"(authorized scope: {scope_display})"
                )
        # Proxy / jump hosts: curl -x, ssh/scp/sftp -J, ProxyJump=, ProxyCommand=.
        _proxy_flags = frozenset(
            {
                "-x",
                "--proxy",
                "--proxies",  # nmap multi-proxy (RH-09)
                "--preproxy",
                "--socks5",
                "--socks5-hostname",
                "--socks4",
                "--socks4a",
                "-J",
                "--jump",
            }
        )

        def _proxy_host_from_val(raw: str) -> str:
            proxy_host = raw.strip().strip("'\"")
            if "://" in proxy_host:
                parsed = urllib.parse.urlparse(proxy_host)
                return (parsed.hostname or "").strip()
            return proxy_host.split("@")[-1].split("/")[0].split(":")[0]

        def _check_proxyjump_val(jump: str) -> None:
            for hop in jump.split(","):
                hop_host = hop.split("@")[-1].split("/")[0].split(":")[0].strip().strip("'\"")
                _assert_host_token_in_scope(hop_host, allowed_items, scope_display)

        skip_proxy_arg = False
        skip_proxy_is_jump = False
        for nxt in tokens[i + 1 :]:
            if skip_proxy_arg:
                raw_proxy = nxt.strip().strip("'\"")
                if skip_proxy_is_jump:
                    _check_proxyjump_val(raw_proxy)
                else:
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(nxt), allowed_items, scope_display
                    )
                skip_proxy_arg = False
                skip_proxy_is_jump = False
                continue
            if not nxt.startswith("-"):
                continue
            # Glued ``-oProxyJump=evil`` / ``-o'ProxyJump=evil'``.
            glued_o = _GLUED_SSH_O_RE.match(nxt.strip("'\"")) or _GLUED_SSH_O_RE.match(nxt)
            if glued_o is None:
                # Also try after stripping quotes around the whole token.
                glued_o = _GLUED_SSH_O_RE.match(nxt.replace("'", "").replace('"', ""))
            if glued_o is not None:
                key = glued_o.group("key").lower()
                val = glued_o.group("val").strip().strip("'\"")
                if key in {"proxycommand", "dynamicforward", "tunnel"}:
                    raise PermissionDeniedError(
                        f"ssh {key} is not allowed under authorized scope "
                        f"(authorized scope: {scope_display})"
                    )
                if key in {"localforward", "remoteforward"}:
                    parts = val.split(":")
                    if len(parts) >= 3:
                        fwd_host = parts[-2].strip().strip("[]")
                        if fwd_host:
                            _assert_host_token_in_scope(
                                fwd_host, allowed_items, scope_display
                            )
                    continue
                _check_proxyjump_val(val)
                continue
            # Glued ``-x11.1.1.1:8080`` / ``-Jbastion`` / ``-Jevil,other``.
            glued_short = _GLUED_PROXY_SHORT_RE.match(nxt)
            if glued_short is not None and not nxt.startswith("--"):
                flag_ch = glued_short.group("flag")
                # ``-x`` proxy / ``-J`` jump only (reject ``-X`` method via case).
                if flag_ch in {"-x", "-J"} and glued_short.group("val")[:1] not in {"", "-"}:
                    glued_val = glued_short.group("val").strip().strip("'\"")
                    if flag_ch == "-J":
                        _check_proxyjump_val(glued_val)
                    else:
                        _assert_host_token_in_scope(
                            _proxy_host_from_val(glued_val),
                            allowed_items,
                            scope_display,
                        )
                    continue
            # Glued long proxy: ``--proxy1.1.1.1:8080`` / ``--socks5-hostname1.1.1.1``.
            # Longest flag first so ``--socks5-hostname`` wins over ``--socks5``.
            glued_long_proxy = False
            for pflag in sorted(
                (p for p in _proxy_flags if p.startswith("--")),
                key=len,
                reverse=True,
            ):
                if nxt.startswith(pflag) and len(nxt) > len(pflag) and nxt[len(pflag)] != "=":
                    glued_val = nxt[len(pflag) :].strip().strip("'\"")
                    if glued_val and glued_val[:1] != "-":
                        _assert_host_token_in_scope(
                            _proxy_host_from_val(glued_val),
                            allowed_items,
                            scope_display,
                        )
                        glued_long_proxy = True
                        break
            if glued_long_proxy:
                continue
            flag = nxt.split("=", 1)[0]
            if flag in _proxy_flags or any(
                flag.startswith(p) and p.startswith("--") for p in _proxy_flags
            ):
                is_jump = flag in {"-J", "--jump"}
                if "=" in nxt:
                    eq_val = nxt.split("=", 1)[1].strip().strip("'\"")
                    if is_jump:
                        _check_proxyjump_val(eq_val)
                    else:
                        _assert_host_token_in_scope(
                            _proxy_host_from_val(eq_val),
                            allowed_items,
                            scope_display,
                        )
                elif flag in _proxy_flags:
                    # Exact flag only — glued forms handled above.
                    skip_proxy_arg = True
                    skip_proxy_is_jump = is_jump
                continue
        # ``-o ProxyJump=bastion`` as two tokens (value may be quoted).
        for j, tok2 in enumerate(tokens[i + 1 :]):
            if tok2 in {"-o", "--option"} and j + 1 < len(tokens[i + 1 :]):
                val = tokens[i + 1 :][j + 1].strip().strip("'\"")
                low = val.lower()
                if low.startswith("proxycommand="):
                    raise PermissionDeniedError(
                        f"ProxyCommand is not allowed under authorized scope "
                        f"(authorized scope: {scope_display})"
                    )
                if low.startswith("proxyjump="):
                    _check_proxyjump_val(val.split("=", 1)[-1])
        # scp/sftp/rsync: ``[user@]host:path`` / ``host::module``; sftp also bare host.
        if base in {"scp", "sftp", "rsync"}:
            skip_jump = False
            for nxt in tokens[i + 1 :]:
                if skip_jump:
                    skip_jump = False
                    continue
                if nxt.startswith("-"):
                    flag = nxt.split("=", 1)[0]
                    if flag in {"-J", "--jump"} and "=" not in nxt:
                        skip_jump = True
                    continue
                scp_m = _SCP_REMOTE_RE.match(nxt)
                # rsync daemon: ``host::module``
                if scp_m is None and base == "rsync" and "::" in nxt:
                    candidate = nxt.split("::", 1)[0].split("@")[-1]
                elif scp_m is not None:
                    candidate = (scp_m.group("host") or "").strip("[]")
                elif base == "sftp":
                    # Bare ``sftp bastion`` / ``sftp user@bastion``.
                    candidate = nxt.split("@")[-1].split("/")[0]
                else:
                    continue
                if not candidate:
                    continue
                _assert_host_token_in_scope(candidate, allowed_items, scope_display)
                break
            continue
        # openssl s_client -connect host:port / -proxy host:port (skip subcommands).
        if base == "openssl":
            skip_ssl_arg = False
            for nxt in tokens[i + 1 :]:
                if skip_ssl_arg:
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(nxt), allowed_items, scope_display
                    )
                    skip_ssl_arg = False
                    continue
                if not nxt.startswith("-"):
                    continue
                glued = _glued_host_flag_value(
                    nxt,
                    short=frozenset(),
                    long=frozenset({"-connect", "-proxy", "--proxy"}),
                )
                if glued:
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(glued), allowed_items, scope_display
                    )
                    continue
                flag = nxt.split("=", 1)[0]
                if flag in {"-connect", "-proxy", "--proxy"}:
                    if "=" in nxt:
                        _assert_host_token_in_scope(
                            _proxy_host_from_val(nxt.split("=", 1)[1]),
                            allowed_items,
                            scope_display,
                        )
                    else:
                        skip_ssl_arg = True
            continue
        # git remote URLs are covered by ``_NON_HTTP_URL_RE`` (``git://``); skip argv noise.
        if base == "git":
            continue
        # ``host``/``nslookup`` — every non-flag token is a name or DNS server.
        if base in {"host", "nslookup"}:
            for nxt in tokens[i + 1 :]:
                if nxt.startswith("-"):
                    continue
                _assert_host_token_in_scope(
                    nxt.split("@")[-1].split("/")[0].strip().strip("'\""),
                    allowed_items,
                    scope_display,
                )
            continue
        # docker/podman daemon endpoints: ``-H tcp://host``, ``--url``, ``context use``.
        if base in {"docker", "podman"}:
            # ``docker context use`` / ``podman system connection use`` hide the daemon
            # (RH-34 / RH-41).
            rest_lower = [t.lower() for t in tokens[i + 1 :]]
            for j in range(len(rest_lower) - 1):
                if rest_lower[j] == "context" and rest_lower[j + 1] == "use":
                    raise PermissionDeniedError(
                        f"{base} context use is not allowed under authorized scope "
                        f"(authorized scope: {scope_display}); pass an explicit -H/--host"
                    )
                if (
                    j + 2 < len(rest_lower)
                    and rest_lower[j] == "system"
                    and rest_lower[j + 1] == "connection"
                    and rest_lower[j + 2] in {"use", "default", "remove"}
                ):
                    raise PermissionDeniedError(
                        f"{base} system connection {rest_lower[j + 2]} is not allowed "
                        f"under authorized scope (authorized scope: {scope_display}); "
                        f"pass an explicit -H/--host/--connection"
                    )
            skip_daemon = False
            for nxt in tokens[i + 1 :]:
                if skip_daemon:
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(nxt), allowed_items, scope_display
                    )
                    skip_daemon = False
                    continue
                if not nxt.startswith("-"):
                    continue
                glued = _glued_host_flag_value(
                    nxt,
                    short=frozenset({"-H"}),
                    long=frozenset({"--host", "--url", "--connection"}),
                )
                if glued:
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(glued), allowed_items, scope_display
                    )
                    continue
                flag = nxt.split("=", 1)[0]
                if flag in {"-H", "--host", "--url", "--connection"}:
                    if "=" in nxt:
                        _assert_host_token_in_scope(
                            _proxy_host_from_val(nxt.split("=", 1)[1]),
                            allowed_items,
                            scope_display,
                        )
                    else:
                        skip_daemon = True
            continue
        # skopeo/buildah: ``docker://registry/image`` hosts (RH-42). Do not treat
        # verbs (``copy``/``push``) as hosts.
        if base in {"skopeo", "buildah"}:
            for nxt in tokens[i + 1 :]:
                raw = nxt.strip().strip("'\"")
                low = raw.lower()
                if "://" in low:
                    # docker://host/path | docker-daemon:… | oci:…
                    parsed = urllib.parse.urlparse(
                        raw if "://" in raw else f"docker://{raw}"
                    )
                    host = (parsed.hostname or "").strip()
                    if not host and low.startswith("docker://"):
                        host = raw.split("://", 1)[1].split("/")[0].split(":")[0]
                    if host:
                        _assert_host_token_in_scope(host, allowed_items, scope_display)
            continue
        # kubectl/oc/helm/kustomize: API host via kubeconfig already blocked above.
        # Do not treat verbs (``get``/``list``) as hosts — that false-positives
        # in-engagement cluster work. Opaque ``--context`` / ``use-context`` hide
        # the real API server (RH-40).
        if base in {"kubectl", "oc", "helm", "kustomize"}:
            rest = tokens[i + 1 :]
            rest_lower = [t.lower().strip().strip("'\"") for t in rest]
            for j, low in enumerate(rest_lower):
                # Local API/port pivots hide the real cluster egress (RH-42).
                if low in {"proxy", "port-forward", "port_forward"}:
                    raise PermissionDeniedError(
                        f"{base} {low} is not allowed under authorized scope "
                        f"(authorized scope: {scope_display})"
                    )
                if low in {"use-context", "set-context", "rename-context"}:
                    raise PermissionDeniedError(
                        f"{base} {low} is not allowed under authorized scope "
                        f"(authorized scope: {scope_display}); pass an explicit "
                        f"--server with an in-scope API host"
                    )
                if low == "config" and j + 1 < len(rest_lower):
                    nxt_cmd = rest_lower[j + 1]
                    if nxt_cmd in {
                        "use-context",
                        "set-context",
                        "rename-context",
                        "set-cluster",
                    }:
                        raise PermissionDeniedError(
                            f"{base} config {nxt_cmd} is not allowed under "
                            f"authorized scope (authorized scope: {scope_display})"
                        )
            skip_server = False
            for nxt in rest:
                if skip_server:
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(nxt), allowed_items, scope_display
                    )
                    skip_server = False
                    continue
                if not nxt.startswith("-"):
                    continue
                glued = _glued_host_flag_value(
                    nxt,
                    short=frozenset(),
                    long=frozenset({"--server", "--host"}),
                )
                if glued:
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(glued), allowed_items, scope_display
                    )
                    continue
                flag = nxt.split("=", 1)[0]
                if flag in {"--context", "--kube-context", "--cluster"} or (
                    flag.startswith("--context")
                    or flag.startswith("--kube-context")
                    or flag.startswith("--cluster")
                ):
                    raise PermissionDeniedError(
                        f"{base} {flag} is not allowed under authorized scope "
                        f"(authorized scope: {scope_display}); pass an explicit "
                        f"--server with an in-scope API host"
                    )
                if flag in {"--server", "--host"}:
                    if "=" in nxt:
                        _assert_host_token_in_scope(
                            _proxy_host_from_val(nxt.split("=", 1)[1]),
                            allowed_items,
                            scope_display,
                        )
                    else:
                        skip_server = True
            continue
        # DB / RDP / WinRM host flags (``mysql -h``, ``xfreerdp /v:``).
        if base in {
            "mysql",
            "psql",
            "redis-cli",
            "mongosh",
            "mongo",
            "clickhouse-client",
            "clickhouse",
            "cqlsh",
            "evil-winrm",
            "xfreerdp",
            "impacket-psexec",
            "psexec.py",
            "impacket-wmiexec",
            "wmiexec.py",
            "impacket-smbexec",
            "smbexec.py",
            "impacket-atexec",
            "atexec.py",
            "rdesktop",
            "freerdp",
            "sqlcmd",
            "mssql-cli",
            "osql",
            "smbmap",
        }:
            skip_db = False
            for nxt in tokens[i + 1 :]:
                if skip_db:
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(nxt), allowed_items, scope_display
                    )
                    skip_db = False
                    continue
                # ``xfreerdp /v:evilhost`` / ``/v:evilhost:3389``.
                if nxt.lower().startswith("/v:"):
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(nxt.split(":", 1)[1]),
                        allowed_items,
                        scope_display,
                    )
                    continue
                if not nxt.startswith("-"):
                    # Positional host (impacket-psexec / bare redis-cli target).
                    cand = nxt.split("@")[-1].split("/")[0].strip().strip("'\"")
                    if cand and not cand.startswith("/"):
                        _assert_host_token_in_scope(cand, allowed_items, scope_display)
                    continue
                glued = _glued_host_flag_value(
                    nxt,
                    short=frozenset({"-h", "-H", "-i", "-S"}),
                    long=frozenset({"--host", "--ip", "--server"}),
                )
                if glued:
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(glued), allowed_items, scope_display
                    )
                    continue
                flag = nxt.split("=", 1)[0]
                if flag in {"-h", "--host", "-H", "-i", "--ip", "-S", "--server"}:
                    if "=" in nxt:
                        _assert_host_token_in_scope(
                            _proxy_host_from_val(nxt.split("=", 1)[1]),
                            allowed_items,
                            scope_display,
                        )
                    else:
                        skip_db = True
            continue
        # Online brute / pivot helpers: host via ``-h`` or positional (skip service token).
        if base in {
            "hydra",
            "medusa",
            "ncrack",
            "patator",
            "ligolo-ng",
            "ligolo",
        }:
            mode: str | None = None  # "host" | "skip"
            _brute_skip_flags = frozenset(
                {
                    "-l",
                    "-p",
                    "-L",
                    "-P",
                    "-C",
                    "-u",
                    "-U",
                    "-e",
                    "-f",
                    "-M",
                    "-m",
                    "-o",
                    "-O",
                    "-t",
                    "-T",
                    "-w",
                    "-W",
                    "-s",
                    "-S",
                    "-x",
                    "-y",
                    "-n",
                    "-c",
                    "-R",
                    "-b",
                    "-F",
                    "-q",
                    "-I",
                    "-V",
                    "-v",
                    "-d",
                    "-D",
                }
            )
            for nxt in tokens[i + 1 :]:
                if mode == "host":
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(nxt), allowed_items, scope_display
                    )
                    break
                if mode == "skip":
                    mode = None
                    continue
                if not nxt.startswith("-"):
                    cand = nxt.split("@")[-1].split("/")[0].split(":")[0].strip().strip("'\"")
                    if not cand or cand.lower() in _BRUTE_SERVICE_TOKENS:
                        continue
                    _assert_host_token_in_scope(cand, allowed_items, scope_display)
                    break
                glued = _glued_host_flag_value(
                    nxt,
                    short=frozenset({"-h", "-H", "-i"}),
                    long=frozenset({"--host", "--ip"}),
                )
                if glued:
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(glued), allowed_items, scope_display
                    )
                    break
                flag = nxt.split("=", 1)[0]
                if flag in {"-h", "--host", "-H", "-i", "--ip"}:
                    if "=" in nxt:
                        _assert_host_token_in_scope(
                            _proxy_host_from_val(nxt.split("=", 1)[1]),
                            allowed_items,
                            scope_display,
                        )
                        break
                    mode = "host"
                    continue
                if flag in _brute_skip_flags and "=" not in nxt:
                    mode = "skip"
            continue
        # wget ``-e http_proxy=evil:8080`` execute directives.
        if base == "wget":
            skip_exec = False
            for nxt in tokens[i + 1 :]:
                if skip_exec:
                    low = nxt.lower()
                    if "proxy" in low and "=" in nxt:
                        _assert_host_token_in_scope(
                            _proxy_host_from_val(nxt.split("=", 1)[1]),
                            allowed_items,
                            scope_display,
                        )
                    skip_exec = False
                    continue
                if not nxt.startswith("-"):
                    continue
                flag = nxt.split("=", 1)[0]
                if flag in {"-e", "--execute"}:
                    if "=" in nxt:
                        low = nxt.lower()
                        if "proxy" in low:
                            _assert_host_token_in_scope(
                                _proxy_host_from_val(nxt.split("=", 1)[-1]),
                                allowed_items,
                                scope_display,
                            )
                    else:
                        skip_exec = True
        # sshuttle ``-r user@host`` full-tunnel remote (engagement-bound when scope set).
        if base == "sshuttle":
            skip_r = False
            for nxt in tokens[i + 1 :]:
                if skip_r:
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(nxt), allowed_items, scope_display
                    )
                    skip_r = False
                    continue
                # ``0/0`` / ``0.0.0.0/0`` / ``::/0`` = full-tunnel egress pivot (RH-30).
                bare = nxt.strip().strip("'\"")
                if bare in {"0/0", "0.0.0.0/0", "::/0", "0::/0"}:
                    raise PermissionDeniedError(
                        f"sshuttle full-tunnel {bare} is not allowed under authorized "
                        f"scope (authorized scope: {scope_display})"
                    )
                if not nxt.startswith("-"):
                    continue
                flag = nxt.split("=", 1)[0]
                if flag in {"-r", "--remote"}:
                    if "=" in nxt:
                        _assert_host_token_in_scope(
                            _proxy_host_from_val(nxt.split("=", 1)[1]),
                            allowed_items,
                            scope_display,
                        )
                    else:
                        skip_r = True
            continue
        # chisel ``client host:port …`` / crackmapexec|nxc ``smb host``.
        if base in {"chisel", "crackmapexec", "cme", "nxc", "netexec"}:
            # Reverse SOCKS / R:socks via an in-scope hop still pivots out (RH-29).
            # Scan *all* remotes first — host validation below breaks after the
            # first hop and must not skip a trailing ``R:socks``.
            if base == "chisel":
                for nxt in tokens[i + 1 :]:
                    low = nxt.lower().strip().strip("'\"")
                    # Client remotes + server ``--socks5`` listener (RH-29 / RH-41).
                    if (
                        low in {"r:socks", "socks", "socks5", "socks4", "--socks5", "--socks4", "--socks"}
                        or low.startswith("r:socks")
                        or low.startswith("--socks5")
                        or low.startswith("--socks4")
                        or ":socks" in low
                    ):
                        raise PermissionDeniedError(
                            f"chisel SOCKS reverse pivot is not allowed under "
                            f"authorized scope (authorized scope: {scope_display})"
                        )
            skip_sub = base == "chisel"
            for nxt in tokens[i + 1 :]:
                low = nxt.lower().strip().strip("'\"")
                if nxt.startswith("-"):
                    continue
                if skip_sub and low in {"client", "server"}:
                    skip_sub = False
                    continue
                if base != "chisel" and low in {
                    "smb",
                    "ssh",
                    "winrm",
                    "mssql",
                    "ldap",
                    "rdp",
                    "ftp",
                    "vnc",
                }:
                    continue
                cand = nxt.split("@")[-1].split("/")[0].split(":")[0].strip().strip("'\"")
                if cand:
                    _assert_host_token_in_scope(cand, allowed_items, scope_display)
                    break
            continue
        # nikto ``-h host`` / ``-host``.
        if base == "nikto":
            skip_h = False
            for nxt in tokens[i + 1 :]:
                if skip_h:
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(nxt), allowed_items, scope_display
                    )
                    skip_h = False
                    continue
                if not nxt.startswith("-"):
                    continue
                glued = _glued_host_flag_value(
                    nxt,
                    short=frozenset({"-h", "-H"}),
                    long=frozenset({"--host", "-host"}),
                )
                if glued:
                    _assert_host_token_in_scope(
                        _proxy_host_from_val(glued), allowed_items, scope_display
                    )
                    continue
                flag = nxt.split("=", 1)[0]
                if flag in {"-h", "-host", "--host"}:
                    if "=" in nxt:
                        _assert_host_token_in_scope(
                            _proxy_host_from_val(nxt.split("=", 1)[1]),
                            allowed_items,
                            scope_display,
                        )
                    else:
                        skip_h = True
            continue
        # ansible ``-i host,`` inventory (engagement-bound when scope set).
        if base in {"ansible", "ansible-playbook", "ansible-inventory"}:
            skip_inv = False
            for nxt in tokens[i + 1 :]:
                if skip_inv:
                    # ``host,`` / ``host1,host2`` / path — check host-like tokens only.
                    for part in nxt.replace(",", " ").split():
                        part = part.strip().strip("'\"")
                        if not part or "/" in part or part.endswith((".yml", ".yaml", ".ini")):
                            continue
                        _assert_host_token_in_scope(part, allowed_items, scope_display)
                    skip_inv = False
                    continue
                if not nxt.startswith("-"):
                    # Positional pattern host limit (``ansible all`` is not a target host).
                    continue
                flag = nxt.split("=", 1)[0]
                if flag in {"-i", "--inventory", "--inventory-file"}:
                    if "=" in nxt:
                        for part in nxt.split("=", 1)[1].replace(",", " ").split():
                            part = part.strip().strip("'\"")
                            if not part or "/" in part or part.endswith(
                                (".yml", ".yaml", ".ini")
                            ):
                                continue
                            _assert_host_token_in_scope(part, allowed_items, scope_display)
                    else:
                        skip_inv = True
            continue

        def _check_ssh_forward_spec(spec: str) -> None:
            """Fail-closed on ``-L``/``-R`` ``[bind:]port:host:hostport`` targets."""
            parts = spec.strip().strip("'\"").split(":")
            if len(parts) >= 3:
                fwd_host = parts[-2].strip().strip("[]")
                if fwd_host:
                    _assert_host_token_in_scope(fwd_host, allowed_items, scope_display)

        _ssh_opt_flags = frozenset({"-o", "--option"})
        _ssh_forward_flags = frozenset({"-L", "-R", "-D"})
        _cred_flags = frozenset({"-U", "--user", "--username"})
        skip_next_port = False
        skip_ssh_o_val = False
        skip_forward_spec = False
        skip_cred_arg = False
        for nxt in tokens[i + 1 :]:
            if skip_ssh_o_val:
                # Spaced ``-o DynamicForward=9050`` / ``-o ProxyJump=evil`` (RH-08).
                opt = nxt.strip().strip("'\"")
                opt_key, sep, opt_val = opt.partition("=")
                key_l = opt_key.lower()
                if key_l in {"proxycommand", "dynamicforward", "tunnel"}:
                    raise PermissionDeniedError(
                        f"ssh {key_l} is not allowed under authorized scope "
                        f"(authorized scope: {scope_display})"
                    )
                if key_l == "proxyjump" and sep:
                    _check_proxyjump_val(opt_val)
                elif key_l in {"localforward", "remoteforward"} and sep:
                    _check_ssh_forward_spec(opt_val)
                skip_ssh_o_val = False
                continue
            if skip_next_port:
                skip_next_port = False
                continue
            if skip_forward_spec:
                _check_ssh_forward_spec(nxt)
                skip_forward_spec = False
                continue
            if skip_cred_arg:
                skip_cred_arg = False
                continue
            if nxt.startswith("-"):
                flag = nxt.split("=", 1)[0]
                ssh_opt = base in {"ssh", "autossh", "scp", "sftp"} and (
                    flag in _ssh_opt_flags
                    or flag.startswith("-o")
                    or flag.startswith("--option")
                )
                jump_opt = flag in {"-J", "--jump"}
                # TUN/TAP device forwarding ``-w`` / ``-w0:0`` (RH-19).
                if base in {"ssh", "autossh"} and (flag == "-w" or re.match(r"^-w[\d:]", flag)):
                    raise PermissionDeniedError(
                        f"ssh -w TUN/TAP tunnel is not allowed under authorized scope "
                        f"(authorized scope: {scope_display})"
                    )
                # autossh ``-M 0`` monitor port — skip so ``0`` is not treated as a host.
                if base == "autossh" and flag in {"-M", "--monitor"}:
                    if "=" not in nxt:
                        skip_next_port = True
                    continue
                # Spaced ``-D 9050`` and glued ``-D9050`` / ``-L8080:h:80`` (RH-08).
                glued_dyn = bool(re.match(r"^-D\d", flag))
                glued_lr = bool(re.match(r"^-[LR]\d", flag))
                forward_opt = base in {"ssh", "autossh"} and (
                    flag in _ssh_forward_flags or glued_dyn or glued_lr
                )
                if forward_opt:
                    if flag == "-D" or glued_dyn:
                        # DynamicForward creates a local SOCKS pivot — blocked under scope.
                        raise PermissionDeniedError(
                            f"ssh -D DynamicForward is not allowed under authorized scope "
                            f"(authorized scope: {scope_display})"
                        )
                    if glued_lr:
                        # ``-L8080:host:80`` / ``-R8080:host:80`` — host is after first port.
                        _check_ssh_forward_spec(flag[2:])
                        continue
                    if "=" in nxt:
                        if flag in {"-L", "-R"}:
                            _check_ssh_forward_spec(nxt.split("=", 1)[1])
                    else:
                        skip_forward_spec = flag in {"-L", "-R"}
                    continue
                if (
                    flag in _port_flags
                    or flag.lower().startswith("-p")
                    or ssh_opt
                    or jump_opt
                ):
                    # ``-o Key=val``, ``-J bastion``, ``-p 22``.
                    if "=" not in nxt and flag in _ssh_opt_flags:
                        skip_ssh_o_val = True
                    elif "=" not in nxt and (
                        flag in _port_flags | {"-J", "--jump"}
                    ):
                        skip_next_port = True
                    elif "=" not in nxt and flag.lower().startswith("-p") and len(flag) <= 2:
                        skip_next_port = True
                    continue
                # ``rpcclient -U user%pass`` / ``smbclient -U …`` — skip credential token.
                if base in {"rpcclient", "smbclient", "impacket-smbclient"} and (
                    flag in _cred_flags
                ):
                    if "=" not in nxt:
                        skip_cred_arg = True
                    continue
                continue
            if "://" in nxt:
                break  # URLs handled by scheme / http(s) checks
            # UNC / smbclient ``//host/share`` or Windows ``\\host\share``.
            unc = nxt.replace("\\", "/").lstrip("/")
            # socat ``TCP:evil-host:80`` / ``SOCKS4A:proxy:dest:80`` address forms.
            nxt_norm = nxt.replace("\\", "/")
            socks_m = _SOCAT_SOCKS_RE.match(nxt_norm)
            socat_m = None if socks_m else _SOCAT_ADDR_RE.match(nxt_norm)
            if socks_m:
                # Fail-closed on both proxy hop and destination.
                _assert_host_token_in_scope(
                    (socks_m.group("proxy") or "").strip(),
                    allowed_items,
                    scope_display,
                )
                raw_host = (socks_m.group("v6") or socks_m.group("host") or "").strip()
            elif socat_m:
                raw_host = (socat_m.group("v6") or socat_m.group("host") or "").strip()
            else:
                raw_host = unc.split("@")[-1].split("/")[0]
            # IPv6 (``2001:db8::1`` / ``[2001:db8::1]``) — do not truncate on ``:``.
            # (socat already extracted the host; skip the multi-colon IPv6 bail.)
            if not (socks_m or socat_m) and (
                raw_host.startswith("[") or raw_host.count(":") >= 2
            ):
                break
            candidate = raw_host.split(":")[0].strip().strip("'\"")  # strip port + quotes
            # Empty / quote-only tokens (``rpcclient -U '' evil``) — keep scanning.
            if not candidate:
                continue
            # ``user%pass`` credential tokens — keep scanning for the real host.
            if "%" in candidate:
                continue
            # Integer / short IPv4 hosts (``curl 0`` → 0.0.0.0).
            if candidate.isdigit() or re.fullmatch(r"0[xX][0-9a-fA-F]+", candidate):
                int_ip = _try_int_ip(candidate)
                if int_ip is not None and not ip_in_scope(int_ip, allowed_items):
                    raise PermissionDeniedError(
                        f"Target IP {int_ip} is out of authorized scope: {scope_display}"
                    )
                break
            if "." in candidate or candidate.lower() == "localhost":
                # IDN / homoglyph domains are often missed by ASCII ``_DOMAIN_RE``.
                if any(ord(ch) > 127 for ch in candidate):
                    dom = candidate.lower().rstrip(".")
                    try:
                        puny = candidate.encode("idna").decode("ascii").lower().rstrip(".")
                    except (UnicodeError, ValueError):
                        puny = dom
                    if not (
                        domain_in_scope(dom, allowed_items)
                        or domain_in_scope(puny, allowed_items)
                    ):
                        raise PermissionDeniedError(
                            f"Target domain {dom} is out of authorized scope: {scope_display}"
                        )
                break
            if _SINGLE_LABEL_RE.match(candidate):
                if not domain_in_scope(candidate.lower(), allowed_items):
                    raise PermissionDeniedError(
                        f"Target host {candidate.lower()} is out of authorized scope: "
                        f"{scope_display}"
                    )
                break
            # Non-host token — keep scanning (do not stop before the real target).
            continue

    for ip_str in found_ips:
        if not ip_in_scope(ip_str, allowed_items):
            raise PermissionDeniedError(
                f"Target IP {ip_str} is out of authorized scope: {scope_display}"
            )

    for domain in found_domains:
        if not domain_in_scope(domain, allowed_items):
            raise PermissionDeniedError(
                f"Target domain {domain} is out of authorized scope: {scope_display}"
            )

    # Fail closed on http(s) URL hosts (including percent-encoded / integer IPv4 forms).
    decoded = _decode_for_extract(command)
    for url in _HTTP_URL_RE.findall(decoded):
        parsed = urllib.parse.urlparse(url)
        host = urllib.parse.unquote((parsed.hostname or "").strip()).lower()
        if not host:
            raise PermissionDeniedError(
                f"URL host could not be parsed for scope check: {url!r} "
                f"(authorized scope: {scope_display})"
            )
        int_ip = _try_int_ip(host)
        if int_ip is not None:
            if not ip_in_scope(int_ip, allowed_items):
                raise PermissionDeniedError(
                    f"Target IP {int_ip} is out of authorized scope: {scope_display}"
                )
            continue
        hex_dotted = _expand_hex_dotted_ipv4(host)
        if hex_dotted is not None:
            if not ip_in_scope(hex_dotted, allowed_items):
                raise PermissionDeniedError(
                    f"Target IP {hex_dotted} is out of authorized scope: {scope_display}"
                )
            continue
        inet_aton = _expand_inet_aton_ipv4(host)
        if inet_aton is not None:
            if not ip_in_scope(inet_aton, allowed_items):
                raise PermissionDeniedError(
                    f"Target IP {inet_aton} is out of authorized scope: {scope_display}"
                )
            continue
        short_ip = _expand_short_ipv4(host)
        if short_ip is not None:
            if not ip_in_scope(short_ip, allowed_items):
                raise PermissionDeniedError(
                    f"Target IP {short_ip} is out of authorized scope: {scope_display}"
                )
            continue
        if _IPV4_OCTAL_RE.fullmatch(host):
            try:
                dotted = ".".join(str(int(p, 8)) for p in host.split("."))
            except ValueError as exc:
                raise PermissionDeniedError(
                    f"URL host could not be parsed for scope check: {url!r} "
                    f"(authorized scope: {scope_display})"
                ) from exc
            if not ip_in_scope(dotted, allowed_items):
                raise PermissionDeniedError(
                    f"Target IP {dotted} is out of authorized scope: {scope_display}"
                )
            continue
        try:
            ip = str(ipaddress.ip_address(host))
        except ValueError:
            if not domain_in_scope(host, allowed_items):
                raise PermissionDeniedError(
                    f"Target domain {host} is out of authorized scope: {scope_display}"
                )
        else:
            if not ip_in_scope(ip, allowed_items):
                raise PermissionDeniedError(
                    f"Target IP {ip} is out of authorized scope: {scope_display}"
                )
