# ============================================================
# threat_rules.py — STRIDE Threat Rules
# Yahan har service ke liye threats defined hain
# ============================================================

THREAT_RULES = {
    "FTP": {
        "Spoofing":               "FTP lacks strong authentication, allowing attackers to impersonate legitimate users.",
        "Information Disclosure": "FTP transmits data in plain text, exposing credentials and file contents to interception.",
        "Tampering":              "FTP traffic can be intercepted and modified by a man-in-the-middle attacker.",
    },
    "HTTP": {
        "Spoofing":               "HTTP allows attackers to create fake websites and impersonate legitimate services.",
        "Information Disclosure": "HTTP traffic is unencrypted, making sensitive data visible to network sniffers.",
        "Tampering":              "HTTP requests can be modified in transit without detection.",
    },
    "HTTPS": {
        "Repudiation":            "HTTPS logs can be manipulated, allowing users to deny performing certain actions.",
    },
    "SSH": {
        "Spoofing":               "Weak or reused SSH keys can allow attackers to impersonate trusted hosts.",
        "Elevation of Privilege": "Misconfigured SSH settings may allow unauthorized users to gain root-level access.",
    },
    "TELNET": {
        "Spoofing":               "Telnet provides no authentication mechanism, allowing any user to connect freely.",
        "Information Disclosure": "Telnet transmits all data including passwords in plain text over the network.",
        "Tampering":              "Telnet sessions are vulnerable to hijacking and in-transit data modification.",
        "Elevation of Privilege": "Telnet misconfigurations can be exploited to gain administrative system access.",
    },
    "SMB": {
        "Tampering":              "Unauthorized users may modify or delete files on exposed SMB shares.",
        "Elevation of Privilege": "SMB vulnerabilities can be exploited to escalate privileges on the target system.",
        "Denial of Service":      "SMB flooding attacks can overwhelm system resources, causing service disruption.",
    },
    "DNS": {
        "Spoofing":               "DNS spoofing allows attackers to redirect users to malicious websites.",
        "Tampering":              "DNS records can be altered to hijack legitimate traffic to attacker-controlled servers.",
    },
    "SMTP": {
        "Spoofing":               "SMTP allows email sender addresses to be forged, enabling phishing attacks.",
        "Repudiation":            "Email senders can deny sending messages due to lack of non-repudiation controls.",
        "Information Disclosure": "Email content transmitted over SMTP can be intercepted without encryption.",
    },
    "RDP": {
        "Spoofing":               "RDP is vulnerable to brute-force attacks, allowing unauthorized remote login.",
        "Elevation of Privilege": "RDP vulnerabilities can be exploited to gain full administrative control of the system.",
        "Denial of Service":      "RDP flood attacks can crash or make the remote desktop service unavailable.",
    },
}

# Agar No Authentication ho toh extra threats
NO_AUTH_THREATS = {
    "Spoofing":               "No authentication is configured — any user can access the system without verification.",
    "Elevation of Privilege": "Without authentication controls, direct administrative access may be obtainable.",
}

# Agar No Encryption ho toh extra threats
NO_ENCRYPTION_THREATS = {
    "Information Disclosure": "No encryption is in place — all network traffic is readable by potential attackers.",
    "Tampering":              "Unencrypted data can be intercepted and silently modified during transmission.",
}