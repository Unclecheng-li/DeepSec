"""Remediation rule definitions — extracted from intel/remediation.py.

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: S4 修复 — 将 20 条规则定义从 remediation.py（1655 行）提取到独立模块，
         引擎逻辑与规则数据分离，提升可维护性。
"""

from __future__ import annotations

from typing import Dict

from deepsec.spear.intel.remediation import (
    Remediation,
    RemediationPriority,
    RemediationStep,
    RemediationType,
    _rule,
    _severity_to_priority,
)

# ── SQL Injection ────────────────────────────────────────────────────────────

@_rule(r"sql\s*inject|sqli|blind.*inject|union.*inject")
def _remediate_sqli(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "SQL Injection"),
        finding_severity=finding.get("severity", "Critical"),
        summary="Prevent SQL injection by using parameterized queries, input validation, and ORM frameworks.",
        priority=RemediationPriority.IMMEDIATE,
        steps=[
            RemediationStep(
                type=RemediationType.CODE,
                title="Use parameterized queries (Python)",
                language="python",
                description="Replace string concatenation with parameterized queries.",
                content="""# VULNERABLE — never do this:
# cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# SECURE — use parameterized queries:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Or use an ORM (SQLAlchemy):
user = session.query(User).filter(User.id == user_id).first()""",
            ),
            RemediationStep(
                type=RemediationType.CODE,
                title="Use parameterized queries (PHP)",
                language="php",
                description="Use PDO prepared statements.",
                content="""<?php
// VULNERABLE:
// $stmt = $pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);

// SECURE — use prepared statements:
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $_GET['id']]);
$user = $stmt->fetch();""",
            ),
            RemediationStep(
                type=RemediationType.CODE,
                title="Use parameterized queries (Java)",
                language="java",
                description="Use PreparedStatement instead of Statement.",
                content="""// SECURE — PreparedStatement
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
ResultSet rs = ps.executeQuery();""",
            ),
            RemediationStep(
                type=RemediationType.COMMAND,
                title="Deploy a Web Application Firewall (WAF)",
                language="bash",
                description="Install ModSecurity as an additional defense layer.",
                content="""# Install ModSecurity for Apache
sudo apt install libapache2-mod-security2 -y
sudo a2enmod security2
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
sudo systemctl restart apache2""",
            ),
        ],
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    )


# ── Cross-Site Scripting (XSS) ──────────────────────────────────────────────

@_rule(r"cross.?site\s*script|xss|reflected.*script|stored.*script|dom.*xss")
def _remediate_xss(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Cross-Site Scripting (XSS)"),
        finding_severity=finding.get("severity", "High"),
        summary="Mitigate XSS by encoding output, validating input, and using Content Security Policy headers.",
        priority=RemediationPriority.HIGH,
        steps=[
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Add Content-Security-Policy header (Nginx)",
                language="nginx",
                filename="/etc/nginx/conf.d/security-headers.conf",
                description="CSP prevents inline script execution.",
                content="""add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;""",
            ),
            RemediationStep(
                type=RemediationType.CODE,
                title="Output encoding (Python/Jinja2)",
                language="python",
                description="Ensure all user input is HTML-escaped before rendering.",
                content="""from markupsafe import escape

# In Jinja2 templates, autoescaping is on by default:
#   {{ user_input }}          ← auto-escaped
#   {{ user_input | safe }}   ← DANGEROUS — avoid unless trusted

# In Python code:
safe_output = escape(user_input)""",
            ),
            RemediationStep(
                type=RemediationType.CODE,
                title="Output encoding (JavaScript)",
                language="javascript",
                description="Use textContent instead of innerHTML for user data.",
                content="""// VULNERABLE:
// element.innerHTML = userData;

// SECURE — use textContent:
element.textContent = userData;

// If HTML is needed, use a sanitizer:
// import DOMPurify from 'dompurify';
// element.innerHTML = DOMPurify.sanitize(userData);""",
            ),
        ],
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    )


# ── Command Injection ────────────────────────────────────────────────────────

@_rule(r"command\s*inject|os\s*command|shell\s*inject|rce|remote\s*code\s*exec")
def _remediate_cmd_injection(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Command Injection"),
        finding_severity=finding.get("severity", "Critical"),
        summary="Prevent command injection by avoiding shell calls, using safe APIs, and validating input.",
        priority=RemediationPriority.IMMEDIATE,
        steps=[
            RemediationStep(
                type=RemediationType.CODE,
                title="Use subprocess safely (Python)",
                language="python",
                description="Never use shell=True with user input.",
                content="""import subprocess, shlex

# VULNERABLE:
# os.system(f"ping {user_input}")
# subprocess.call(f"ping {user_input}", shell=True)

# SECURE — use list arguments without shell=True:
result = subprocess.run(
    ["ping", "-c", "4", validated_host],
    capture_output=True, text=True, timeout=10
)""",
            ),
            RemediationStep(
                type=RemediationType.CODE,
                title="Input validation",
                language="python",
                description="Whitelist allowed characters / values.",
                content="""import re

def validate_hostname(host: str) -> bool:
    \"\"\"Allow only valid hostnames/IPs.\"\"\"
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\\-\\.]{0,253}[a-zA-Z0-9]$'
    return bool(re.match(pattern, host))

# Reject any input that doesn't pass validation
if not validate_hostname(user_input):
    raise ValueError("Invalid hostname")""",
            ),
        ],
        references=[
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ],
    )


# ── Open Ports / Unnecessary Services ────────────────────────────────────────

@_rule(r"open\s*port|unnecessary\s*service|exposed\s*port|unneeded.*service|port\s*\d+\s*open")
def _remediate_open_ports(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Open Ports / Unnecessary Services"),
        finding_severity=finding.get("severity", "Medium"),
        summary="Close unnecessary ports and disable unused services to reduce the attack surface.",
        priority=_severity_to_priority(finding.get("severity", "Medium")),
        steps=[
            RemediationStep(
                type=RemediationType.COMMAND,
                title="Identify and stop unnecessary services",
                language="bash",
                description="List listening services and disable unneeded ones.",
                content="""# List all listening ports
sudo ss -tulnp

# Disable and stop an unnecessary service (e.g., telnet)
sudo systemctl disable --now telnet.socket
sudo systemctl disable --now rpcbind

# Remove unnecessary packages
sudo apt purge telnetd rsh-server -y""",
            ),
            RemediationStep(
                type=RemediationType.COMMAND,
                title="Configure firewall (UFW)",
                language="bash",
                description="Allow only required ports.",
                content="""# Enable UFW and set default deny
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow only needed services
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable""",
            ),
            RemediationStep(
                type=RemediationType.COMMAND,
                title="Configure firewall (iptables)",
                language="bash",
                description="Drop traffic to unnecessary ports.",
                content="""# Drop all incoming by default
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow specific ports
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Save rules
sudo netfilter-persistent save""",
            ),
        ],
        references=[
            "https://www.cisecurity.org/benchmark",
            "https://www.nist.gov/cyberframework",
        ],
    )


# ── Weak / Default Credentials ──────────────────────────────────────────────

@_rule(r"weak.*password|default.*cred|brute.?force|weak.*auth|default.*password|password.*policy")
def _remediate_weak_creds(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Weak Credentials"),
        finding_severity=finding.get("severity", "High"),
        summary="Enforce strong password policies, change all default credentials, and implement MFA.",
        priority=RemediationPriority.HIGH,
        steps=[
            RemediationStep(
                type=RemediationType.COMMAND,
                title="Enforce password complexity (Linux PAM)",
                language="bash",
                description="Configure PAM to require strong passwords.",
                content="""# Install password quality module
sudo apt install libpam-pwquality -y

# Configure password requirements
sudo tee /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
dictcheck = 1
EOF""",
            ),
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Enforce SSH key-based authentication",
                language="bash",
                filename="/etc/ssh/sshd_config",
                description="Disable password auth and require SSH keys.",
                content="""# Disable password authentication
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes

# Allow only key-based auth
PubkeyAuthentication yes
AuthenticationMethods publickey

# Restart SSH
# sudo systemctl restart sshd""",
            ),
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://pages.nist.gov/800-63-3/sp800-63b.html",
        ],
    )


# ── SSL/TLS Issues ──────────────────────────────────────────────────────────

@_rule(r"ssl|tls|certificate|cipher|heartbleed|poodle|beast|weak.*crypto|expired.*cert|self.?signed")
def _remediate_ssl(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "SSL/TLS Misconfiguration"),
        finding_severity=finding.get("severity", "High"),
        summary="Harden TLS configuration: use TLS 1.2+, strong ciphers, and valid certificates.",
        priority=RemediationPriority.HIGH,
        steps=[
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Harden Nginx TLS configuration",
                language="nginx",
                filename="/etc/nginx/conf.d/ssl.conf",
                description="Enforce modern TLS with strong ciphers.",
                content="""ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;""",
            ),
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Harden Apache TLS configuration",
                language="apache",
                filename="/etc/apache2/conf-available/ssl-hardening.conf",
                description="Disable weak protocols and ciphers.",
                content="""SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder on
SSLCompression off
SSLSessionTickets off
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" """,
            ),
            RemediationStep(
                type=RemediationType.COMMAND,
                title="Obtain a valid certificate (Let's Encrypt)",
                language="bash",
                description="Replace self-signed or expired certificates.",
                content="""# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Obtain certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Auto-renew
sudo certbot renew --dry-run""",
            ),
        ],
        references=[
            "https://ssl-config.mozilla.org/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
        ],
    )


# ── Missing Security Headers ────────────────────────────────────────────────

@_rule(r"missing.*header|security\s*header|x-frame|x-content|hsts|strict.?transport|clickjack|content.?security.?policy")
def _remediate_headers(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Missing Security Headers"),
        finding_severity=finding.get("severity", "Medium"),
        summary="Add essential HTTP security headers to protect against common web attacks.",
        priority=RemediationPriority.MEDIUM,
        steps=[
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Add security headers (Nginx)",
                language="nginx",
                filename="/etc/nginx/conf.d/security-headers.conf",
                content="""add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;""",
            ),
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Add security headers (Apache)",
                language="apache",
                filename="/etc/apache2/conf-available/security-headers.conf",
                content="""Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

# Enable: sudo a2enconf security-headers && sudo systemctl reload apache2""",
            ),
            RemediationStep(
                type=RemediationType.CODE,
                title="Add security headers (Express.js / Node)",
                language="javascript",
                description="Use the helmet middleware.",
                content="""const helmet = require('helmet');
const app = require('express')();

app.use(helmet());  // Sets all security headers automatically

// Or configure individually:
app.use(helmet.frameguard({ action: 'deny' }));
app.use(helmet.contentSecurityPolicy({
  directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"] }
}));""",
            ),
        ],
        references=[
            "https://owasp.org/www-project-secure-headers/",
            "https://securityheaders.com/",
        ],
    )


# ── Directory Traversal / Path Traversal ─────────────────────────────────────

@_rule(r"directory.*travers|path.*travers|local.*file.*inclu|lfi|\.\.\/|file.*inclusion")
def _remediate_path_traversal(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Path Traversal"),
        finding_severity=finding.get("severity", "High"),
        summary="Prevent path traversal by validating file paths and using chroot/jail mechanisms.",
        priority=RemediationPriority.HIGH,
        steps=[
            RemediationStep(
                type=RemediationType.CODE,
                title="Validate file paths (Python)",
                language="python",
                content="""import os
from pathlib import Path

ALLOWED_DIR = Path("/var/www/uploads").resolve()

def safe_file_access(user_path: str) -> Path:
    \"\"\"Prevent path traversal by resolving and validating paths.\"\"\"
    requested = (ALLOWED_DIR / user_path).resolve()
    if not str(requested).startswith(str(ALLOWED_DIR)):
        raise ValueError("Path traversal detected")
    return requested""",
            ),
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Restrict access in Nginx",
                language="nginx",
                description="Block path traversal patterns.",
                content="""# Block path traversal attempts
location ~ \\.\\. {
    deny all;
    return 403;
}

# Restrict to specific directory
location /uploads/ {
    alias /var/www/uploads/;
    autoindex off;
}""",
            ),
        ],
        references=[
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
        ],
    )


# ── CSRF ─────────────────────────────────────────────────────────────────────

@_rule(r"csrf|cross.?site\s*request\s*forg")
def _remediate_csrf(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Cross-Site Request Forgery (CSRF)"),
        finding_severity=finding.get("severity", "Medium"),
        summary="Implement CSRF tokens and SameSite cookie attributes.",
        priority=RemediationPriority.MEDIUM,
        steps=[
            RemediationStep(
                type=RemediationType.CODE,
                title="CSRF protection (Python/Flask)",
                language="python",
                description="Use Flask-WTF for automatic CSRF protection.",
                content="""from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = os.urandom(32)
csrf = CSRFProtect(app)

# In templates, include the token:
# <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">""",
            ),
            RemediationStep(
                type=RemediationType.CODE,
                title="SameSite cookies (Express.js)",
                language="javascript",
                content="""app.use(session({
  cookie: {
    sameSite: 'strict',  // or 'lax'
    secure: true,
    httpOnly: true,
  }
}));""",
            ),
        ],
        references=[
            "https://owasp.org/www-community/attacks/csrf",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    )


# ── SSH Misconfigurations ────────────────────────────────────────────────────

@_rule(r"ssh.*misconfig|ssh.*weak|openssh.*vuln|ssh.*root|ssh.*permit|ssh.*password")
def _remediate_ssh(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "SSH Misconfiguration"),
        finding_severity=finding.get("severity", "High"),
        summary="Harden SSH configuration: disable root login, use key-based auth, restrict access.",
        priority=RemediationPriority.HIGH,
        steps=[
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Harden sshd_config",
                language="bash",
                filename="/etc/ssh/sshd_config",
                content="""# Disable root login
PermitRootLogin no

# Disable password authentication
PasswordAuthentication no

# Use only SSHv2
Protocol 2

# Limit authentication attempts
MaxAuthTries 3
LoginGraceTime 30

# Disable empty passwords
PermitEmptyPasswords no

# Restrict to specific users/groups
AllowGroups sshusers

# Use strong key exchange and ciphers
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com""",
            ),
            RemediationStep(
                type=RemediationType.COMMAND,
                title="Apply and verify SSH changes",
                language="bash",
                content="""# Validate config before restart
sudo sshd -t

# Restart SSH
sudo systemctl restart sshd

# Verify settings
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication|maxauthtries'""",
            ),
        ],
        references=[
            "https://www.ssh.com/academy/ssh/sshd_config",
            "https://www.cisecurity.org/benchmark/distribution_independent_linux",
        ],
    )


# ── Information Disclosure ───────────────────────────────────────────────────

@_rule(r"info.*disclos|server.*version|version.*disclos|banner.*grab|sensitive.*info.*expos|directory.*listing|stack\s*trace")
def _remediate_info_disclosure(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Information Disclosure"),
        finding_severity=finding.get("severity", "Low"),
        summary="Suppress server version banners, disable directory listings, and remove debug endpoints.",
        priority=_severity_to_priority(finding.get("severity", "Low")),
        steps=[
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Hide server version (Nginx)",
                language="nginx",
                filename="/etc/nginx/nginx.conf",
                content="""# In http block:
server_tokens off;
# Optionally add:
# more_clear_headers Server;""",
            ),
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Hide server version (Apache)",
                language="apache",
                filename="/etc/apache2/conf-available/security.conf",
                content="""ServerTokens Prod
ServerSignature Off
TraceEnable Off""",
            ),
            RemediationStep(
                type=RemediationType.COMMAND,
                title="Disable directory listing",
                language="bash",
                content="""# Nginx — remove autoindex
# autoindex off;  (default, but ensure it's not 'on')

# Apache — remove Indexes option
sudo sed -i 's/Options Indexes/Options -Indexes/' /etc/apache2/apache2.conf
sudo systemctl reload apache2""",
            ),
        ],
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
        ],
    )


# ── Outdated Software / Known CVEs ──────────────────────────────────────────

@_rule(r"outdated|end.?of.?life|eol|unpatched|cve-\d{4}|known.*vuln|update.*required|upgrade.*required")
def _remediate_outdated(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Outdated Software"),
        finding_severity=finding.get("severity", "High"),
        summary="Update affected software to the latest patched version.",
        priority=RemediationPriority.HIGH,
        steps=[
            RemediationStep(
                type=RemediationType.COMMAND,
                title="Update system packages",
                language="bash",
                content="""# Debian/Ubuntu
sudo apt update && sudo apt upgrade -y

# RHEL/CentOS/Rocky
sudo dnf update -y

# Check for security updates only (Debian)
sudo apt list --upgradable 2>/dev/null | grep -i security""",
            ),
            RemediationStep(
                type=RemediationType.COMMAND,
                title="Update specific software",
                language="bash",
                description="Replace <package> with the affected software.",
                content="""# Check installed version
dpkg -l | grep <package>
# or
rpm -qa | grep <package>

# Update specific package
sudo apt install --only-upgrade <package>
# or
sudo dnf update <package>""",
            ),
            RemediationStep(
                type=RemediationType.COMMAND,
                title="Enable automatic security updates",
                language="bash",
                content="""# Debian/Ubuntu — enable unattended upgrades
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades""",
            ),
        ],
        references=[
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "https://nvd.nist.gov/",
        ],
    )


# ── CORS Misconfiguration ───────────────────────────────────────────────────

@_rule(r"cors|cross.?origin|access.?control.?allow|origin.*wildcard")
def _remediate_cors(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "CORS Misconfiguration"),
        finding_severity=finding.get("severity", "Medium"),
        summary="Restrict CORS to specific trusted origins instead of wildcard or reflected origins.",
        priority=RemediationPriority.MEDIUM,
        steps=[
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Fix CORS in Nginx",
                language="nginx",
                content="""# Allow specific origins only (not wildcard *)
set $cors_origin "";
if ($http_origin ~* "^https://(www\\.)?yourdomain\\.com$") {
    set $cors_origin $http_origin;
}
add_header Access-Control-Allow-Origin $cors_origin always;
add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
add_header Access-Control-Allow-Credentials "true" always;""",
            ),
            RemediationStep(
                type=RemediationType.CODE,
                title="Fix CORS in Express.js",
                language="javascript",
                content="""const cors = require('cors');

// VULNERABLE: app.use(cors());  // allows all origins

// SECURE:
app.use(cors({
  origin: ['https://yourdomain.com', 'https://app.yourdomain.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));""",
            ),
        ],
        references=[
            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
        ],
    )


# ── IDOR / Broken Access Control ─────────────────────────────────────────────

@_rule(r"idor|insecure.*direct.*object|broken.*access.*control|privilege.*escalat|unauthorized.*access|access.*control")
def _remediate_idor(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Broken Access Control"),
        finding_severity=finding.get("severity", "High"),
        summary="Implement proper authorization checks on every endpoint and use indirect object references.",
        priority=RemediationPriority.HIGH,
        steps=[
            RemediationStep(
                type=RemediationType.CODE,
                title="Authorization middleware (Python/Flask)",
                language="python",
                content="""from functools import wraps
from flask import abort, g

def require_owner(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        resource = get_resource(kwargs['resource_id'])
        if resource.owner_id != g.current_user.id:
            abort(403)
        return f(*args, **kwargs)
    return decorated

@app.route('/api/documents/<resource_id>')
@require_owner
def get_document(resource_id):
    # User can only access their own documents
    ...""",
            ),
            RemediationStep(
                type=RemediationType.CODE,
                title="Use indirect references",
                language="python",
                description="Map internal IDs to per-user tokens.",
                content="""import secrets

# Instead of: /api/invoice/12345 (sequential, guessable)
# Use: /api/invoice/a7f3b2c9e1d4 (random token per user)

def create_indirect_ref(user_id: int, internal_id: int) -> str:
    token = secrets.token_urlsafe(16)
    cache.set(f"ref:{user_id}:{token}", internal_id, timeout=3600)
    return token""",
            ),
        ],
        references=[
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
        ],
    )


# ── File Upload Vulnerabilities ──────────────────────────────────────────────

@_rule(r"file\s*upload|unrestrict.*upload|malicious.*upload|upload.*vuln|webshell")
def _remediate_upload(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Unrestricted File Upload"),
        finding_severity=finding.get("severity", "High"),
        summary="Validate file types, scan uploads, and store files outside the webroot.",
        priority=RemediationPriority.HIGH,
        steps=[
            RemediationStep(
                type=RemediationType.CODE,
                title="Validate uploads (Python/Flask)",
                language="python",
                content="""import magic
from pathlib import Path

ALLOWED_MIME = {'image/jpeg', 'image/png', 'image/gif', 'application/pdf'}
ALLOWED_EXT = {'.jpg', '.jpeg', '.png', '.gif', '.pdf'}
MAX_SIZE = 10 * 1024 * 1024  # 10 MB
UPLOAD_DIR = Path('/var/uploads')  # Outside webroot!

def validate_upload(file):
    # Check extension
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        raise ValueError(f"Extension {ext} not allowed")
    # Check file size
    file.seek(0, 2)
    if file.tell() > MAX_SIZE:
        raise ValueError("File too large")
    file.seek(0)
    # Check actual MIME type (not just header)
    mime = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0)
    if mime not in ALLOWED_MIME:
        raise ValueError(f"MIME type {mime} not allowed")""",
            ),
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Restrict uploads in Nginx",
                language="nginx",
                content="""# Limit upload size
client_max_body_size 10m;

# Disable script execution in upload directory
location /uploads/ {
    location ~ \\.(php|py|pl|cgi|sh|asp|aspx|jsp)$ {
        deny all;
    }
}""",
            ),
        ],
        references=[
            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        ],
    )


# ── XML External Entity (XXE) ───────────────────────────────────────────────

@_rule(r"xxe|xml.*external.*entity|xml.*inject|xml.*parse")
def _remediate_xxe(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "XML External Entity (XXE)"),
        finding_severity=finding.get("severity", "High"),
        summary="Disable external entity processing in XML parsers.",
        priority=RemediationPriority.HIGH,
        steps=[
            RemediationStep(
                type=RemediationType.CODE,
                title="Disable XXE (Python)",
                language="python",
                content="""import defusedxml.ElementTree as ET

# VULNERABLE: xml.etree.ElementTree.parse(user_input)
# SECURE:
tree = ET.parse(user_input)  # defusedxml blocks XXE by default

# Or with lxml:
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(user_input, parser)""",
            ),
            RemediationStep(
                type=RemediationType.CODE,
                title="Disable XXE (Java)",
                language="java",
                content="""DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);""",
            ),
        ],
        references=[
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        ],
    )


# ── Server-Side Request Forgery (SSRF) ──────────────────────────────────────

@_rule(r"ssrf|server.?side\s*request\s*forg")
def _remediate_ssrf(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Server-Side Request Forgery (SSRF)"),
        finding_severity=finding.get("severity", "High"),
        summary="Validate and restrict outbound requests to prevent SSRF attacks.",
        priority=RemediationPriority.HIGH,
        steps=[
            RemediationStep(
                type=RemediationType.CODE,
                title="URL validation (Python)",
                language="python",
                content="""import ipaddress
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
]

def validate_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    import socket
    ip = socket.gethostbyname(parsed.hostname)
    addr = ipaddress.ip_address(ip)
    for net in BLOCKED_NETWORKS:
        if addr in net:
            return False  # Block internal network access
    return True""",
            ),
        ],
        references=[
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    )


# ── Insecure Deserialization ─────────────────────────────────────────────────

@_rule(r"deserializ|pickle|marshal|insecure.*serial|object.*inject")
def _remediate_deserialization(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Insecure Deserialization"),
        finding_severity=finding.get("severity", "Critical"),
        summary="Avoid deserializing untrusted data; use safe formats like JSON instead of pickle/marshal.",
        priority=RemediationPriority.IMMEDIATE,
        steps=[
            RemediationStep(
                type=RemediationType.CODE,
                title="Replace pickle with JSON (Python)",
                language="python",
                content="""import json

# VULNERABLE:
# import pickle
# data = pickle.loads(user_input)  # RCE risk!

# SECURE:
data = json.loads(user_input)

# If you MUST use pickle, use restricted unpickler:
import pickle, io
class RestrictedUnpickler(pickle.Unpickler):
    ALLOWED = {'builtins': {'range', 'dict', 'list', 'set', 'tuple'}}
    def find_class(self, module, name):
        if module in self.ALLOWED and name in self.ALLOWED[module]:
            return getattr(__import__(module), name)
        raise pickle.UnpicklingError(f"Blocked: {module}.{name}")""",
            ),
        ],
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Incoming_Requests",
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
    )


# ── DNS Zone Transfer ────────────────────────────────────────────────────────

@_rule(r"dns.*zone\s*transfer|axfr|dns.*misconfig")
def _remediate_dns(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "DNS Zone Transfer"),
        finding_severity=finding.get("severity", "Medium"),
        summary="Restrict DNS zone transfers to authorized secondary nameservers only.",
        priority=RemediationPriority.MEDIUM,
        steps=[
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Restrict zone transfers (BIND)",
                language="bash",
                filename="/etc/bind/named.conf.options",
                content="""options {
    allow-transfer { none; };     // Global default: deny all
    allow-query { any; };
};

// Per-zone: allow only secondary NS
zone "example.com" {
    type master;
    file "/etc/bind/db.example.com";
    allow-transfer { 192.168.1.2; };  // Secondary NS IP only
};""",
            ),
        ],
        references=[
            "https://www.cisecurity.org/benchmark/bind",
        ],
    )


# ── SNMP Community Strings ──────────────────────────────────────────────────

@_rule(r"snmp.*community|snmp.*public|snmp.*private|snmp.*default|snmp.*string")
def _remediate_snmp(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "SNMP Default Community String"),
        finding_severity=finding.get("severity", "High"),
        summary="Change default SNMP community strings and upgrade to SNMPv3 with authentication.",
        priority=RemediationPriority.HIGH,
        steps=[
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Configure SNMPv3 (snmpd.conf)",
                language="bash",
                filename="/etc/snmp/snmpd.conf",
                content="""# Remove default community strings
# rocommunity public  ← DELETE THIS
# rwcommunity private ← DELETE THIS

# Use SNMPv3 with auth and encryption
createUser snmpMonitor SHA "StrongAuthPass!" AES "StrongPrivPass!"
rouser snmpMonitor priv

# Restrict access by IP
agentAddress udp:161
com2sec readonly  192.168.1.0/24  secret_community""",
            ),
            RemediationStep(
                type=RemediationType.COMMAND,
                title="Apply SNMP changes",
                language="bash",
                content="""sudo systemctl restart snmpd
# Verify with:
snmpwalk -v3 -u snmpMonitor -l authPriv -a SHA -A "StrongAuthPass!" -x AES -X "StrongPrivPass!" localhost""",
            ),
        ],
        references=[
            "https://www.cisecurity.org/benchmark",
        ],
    )


# ── Exposed Admin / Debug Panels ─────────────────────────────────────────────

@_rule(r"admin.*panel|debug.*mode|debug.*endpoint|exposed.*admin|phpinfo|phpmyadmin|management.*console|dashboard.*exposed")
def _remediate_admin_panels(finding: Dict, match) -> Remediation:
    return Remediation(
        finding_title=finding.get("title", "Exposed Admin/Debug Panel"),
        finding_severity=finding.get("severity", "High"),
        summary="Restrict access to admin and debug endpoints; disable debug mode in production.",
        priority=RemediationPriority.HIGH,
        steps=[
            RemediationStep(
                type=RemediationType.CONFIG,
                title="Restrict admin access (Nginx)",
                language="nginx",
                content="""# Block admin panels from public access
location ~ ^/(admin|phpmyadmin|wp-admin|debug|server-status|server-info) {
    allow 10.0.0.0/8;      # Internal network only
    allow 192.168.0.0/16;
    deny all;
}""",
            ),
            RemediationStep(
                type=RemediationType.COMMAND,
                title="Disable debug mode",
                language="bash",
                content="""# Django — set in settings.py or env:
# DEBUG = False
# ALLOWED_HOSTS = ['yourdomain.com']

# Flask — never run with debug in production:
# app.run(debug=False)

# Remove phpinfo files:
sudo find /var/www -name 'phpinfo.php' -delete
sudo find /var/www -name 'info.php' -delete""",
            ),
        ],
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/",
        ],
    )
