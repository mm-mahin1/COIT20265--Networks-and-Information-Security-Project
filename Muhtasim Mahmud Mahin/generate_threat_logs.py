"""
Generates:
  - threat_logs_gt14.csv  : logs with threat score > 14 (HIGH severity)
  - threat_logs_gt9.csv   : logs with threat score > 9  (MEDIUM+ severity)
  - mixed_test_logs.csv   : mixed log stream for full dashboard demo
"""

import pandas as pd
import random
import datetime
import os

random.seed(42)

# ─────────────────────────────────────────────
# 1.  LOG TEMPLATES
# ─────────────────────────────────────────────

HIGH_TEMPLATES = [
    "possible break in attempt reverse mapping checking getaddrinfo for hostname failed from ip_addr",
    "illegal user admin from ip_addr port_num",
    "unauthorized access attempt to restricted file etc shadow from ip_addr",
    "fatal error authentication subsystem crashed pid terminated",
    "attack detected multiple failed logins from ip_addr port_num exceeded threshold",
    "breach detected new outbound connection ip_addr after repeated login failures",
    "corrupt packet received from ip_addr port_num dropping connection",
    "unauthorized sudo attempt by user guest from ip_addr",
    "illegal login attempt user root from ip_addr port_num preauth",
    "break in attempt detected from ip_addr hostname failed dns lookup",
    "unauthorized privilege escalation attempt by uid from ip_addr",
    "attack pattern detected rapid successive auth failures ip_addr port_num",
]

MEDIUM_TEMPLATES = [
    "failed password for root from ip_addr port_num ssh",
    "invalid user wronguser from ip_addr port_num",
    "authentication failure logname uid euid tty ssh ruser rhost ip_addr",
    "pam_unix sshd auth check pass user unknown",
    "connection closed by invalid user wronguser ip_addr port_num preauth",
    "failed password for invalid user testuser from ip_addr port_num",
    "refused connection from ip_addr port_num policy violation",
    "pam_unix authentication failure user root rhost ip_addr",
    "error maximum authentication attempts exceeded for root from ip_addr port_num",
    "denied connection from ip_addr port_num blacklisted host",
    "failure pam_securetty from ip_addr port_num tty ssh",
    "failed keyboard interactive for root from ip_addr port_num",
    "pam_tally account root denied access from ip_addr attempts exceeded",
    "invalid user deploy from ip_addr connection refused port_num",
]

LOW_TEMPLATES = [
    "exception in io handler for connection ip_addr port_num",
    "timeout waiting for response from hostname ip_addr",
    "unknown service request from ip_addr port_num dropping",
    "abort reconnect to ip_addr port_num failed retrying",
    "bad packet received from ip_addr unexpected sequence num",
    "warning possible dns spoofing detected hostname maps to ip_addr",
    "wrong number of auth attempts from ip_addr port_num",
    "pam_unix sshd session service unknown ignore",
    "exception socket connection reset by peer ip_addr port_num",
    "timeout negotiating key exchange with ip_addr port_num",
]

NORMAL_TEMPLATES = [
    "accepted password for user ubuntu from ip_addr port_num ssh",
    "new session opened for user ubuntu by loginuid num",
    "session closed for user ubuntu",
    "pam_unix sshd session session opened for user ubuntu",
    "server listening on ip_addr port num",
    "received signal num exiting",
    "starting openssh server daemon",
    "reload configuration file sshd config",
    "connection from ip_addr port_num at timestamp",
    "disconnected from user ubuntu ip_addr port_num",
    "accepted publickey for ubuntu from ip_addr port_num",
    "pam_unix crond session session opened for user root",
    "cron pam_unix session opened for user root",
    "service started successfully systemd pid num",
]

# ─────────────────────────────────────────────
# 2.  THREAT SCORING FUNCTION
# ─────────────────────────────────────────────

HIGH_KEYWORDS   = ['break-in', 'unauthorized', 'attack', 'breach', 'fatal', 'corrupt', 'illegal', 'privilege escalation', 'rapid successive']
MEDIUM_KEYWORDS = ['failed', 'invalid', 'refused', 'denied', 'error', 'failure', 'authentication failure', 'check pass user unknown', 'exceeded', 'blacklisted']
LOW_KEYWORDS    = ['exception', 'unknown', 'timeout', 'abort', 'warning', 'bad', 'wrong', 'dropping', 'spoofing']


def compute_threat_score(log_text: str) -> int:
    """
    Keyword-based threat scoring.
    HIGH keyword  → +16 points each
    MEDIUM keyword → +10 points each
    LOW keyword   →  +4 points each
    Max cap: 100
    """
    text = log_text.lower()
    score = 0
    for kw in HIGH_KEYWORDS:
        if kw in text:
            score += 16
    for kw in MEDIUM_KEYWORDS:
        if kw in text:
            score += 10
    for kw in LOW_KEYWORDS:
        if kw in text:
            score += 4
    return min(score, 100)


def severity_label(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 15:
        return "MEDIUM"
    elif score >= 9:
        return "LOW"
    else:
        return "NORMAL"


# ─────────────────────────────────────────────
# 3.  RANDOM IP / PORT HELPERS
# ─────────────────────────────────────────────

def random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def random_port():
    return random.randint(49152, 65535)

def fill_template(template: str) -> str:
    return (template
            .replace("ip_addr", random_ip())
            .replace("port_num", str(random_port()))
            .replace("num", str(random.randint(1, 9999)))
            .replace("hostname", f"host-{random.randint(1,99)}.example.com")
            .replace("uid", str(random.randint(1000, 9999)))
            .replace("timestamp", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
            .replace("pid", str(random.randint(1000, 32768))))


# ─────────────────────────────────────────────
# 4.  LOG GENERATION
# ─────────────────────────────────────────────

def generate_logs(n_high=60, n_medium=80, n_low=60, n_normal=100):
    records = []
    base_time = datetime.datetime(2025, 4, 14, 8, 0, 0)

    all_entries = (
        [(t, "HIGH")   for t in [random.choice(HIGH_TEMPLATES)   for _ in range(n_high)]] +
        [(t, "MEDIUM") for t in [random.choice(MEDIUM_TEMPLATES) for _ in range(n_medium)]] +
        [(t, "LOW")    for t in [random.choice(LOW_TEMPLATES)     for _ in range(n_low)]] +
        [(t, "NORMAL") for t in [random.choice(NORMAL_TEMPLATES) for _ in range(n_normal)]]
    )
    random.shuffle(all_entries)

    for i, (template, true_category) in enumerate(all_entries):
        log_text  = fill_template(template)
        score     = compute_threat_score(log_text)
        severity  = severity_label(score)
        timestamp = base_time + datetime.timedelta(seconds=i * random.randint(5, 45))

        records.append({
            "timestamp":     timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "log_message":   log_text,
            "threat_score":  score,
            "severity":      severity,
            "true_category": true_category,
            "source":        "synthetic_server"
        })

    return pd.DataFrame(records)


# ─────────────────────────────────────────────
# 5.  SAVE OUTPUTS
# ─────────────────────────────────────────────

if __name__ == "__main__":
    output_dir = "threat_logs"
    os.makedirs(output_dir, exist_ok=True)

    df = generate_logs(n_high=80, n_medium=120, n_low=80, n_normal=150)

    # threat score > 14
    df_gt14 = df[df["threat_score"] > 14].reset_index(drop=True)
    df_gt14.to_csv(f"{output_dir}/threat_logs_gt14.csv", index=False)

    # threat score > 9
    df_gt9 = df[df["threat_score"] > 9].reset_index(drop=True)
    df_gt9.to_csv(f"{output_dir}/threat_logs_gt9.csv", index=False)

    # full mixed stream (for dashboard demo)
    df.to_csv(f"{output_dir}/mixed_test_logs.csv", index=False)

    print("=" * 60)
    print("THREAT LOG GENERATION COMPLETE")
    print("=" * 60)
    print(f"Total logs generated     : {len(df)}")
    print(f"Threat score > 14        : {len(df_gt14)} logs  → threat_logs_gt14.csv")
    print(f"Threat score > 9         : {len(df_gt9)} logs  → threat_logs_gt9.csv")
    print(f"Full mixed stream        : {len(df)} logs  → mixed_test_logs.csv")
    print()
    print("Severity breakdown (full stream):")
    print(df["severity"].value_counts().to_string())
    print()
    print("Score stats:")
    print(df["threat_score"].describe().to_string())
    print()
    print(f"Files saved to: ./{output_dir}/")
