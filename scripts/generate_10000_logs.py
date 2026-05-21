from pathlib import Path


OUTPUT_FILE = Path(__file__).resolve().parents[1] / "data" / "sample_10000_mixed_logs.log"


def build_log_line(index: int) -> tuple[str, str]:
    hour = 9 + (index % 9)
    minute = index % 60
    second = (index * 7) % 60
    timestamp = f"2026-05-19 {hour:02d}:{minute:02d}:{second:02d}"

    internal_ip = f"192.168.1.{10 + (index % 80)}"
    attacker_ip = f"45.83.12.{1 + (index % 40)}"
    server_ip = f"10.0.0.{1 + (index % 20)}"

    bucket = index % 10

    if bucket < 4:
        templates = [
            f"May 19 {hour:02d}:{minute:02d}:{second:02d} ubuntu-server systemd[1]: Started Daily apt download activities",
            f"May 19 {hour:02d}:{minute:02d}:{second:02d} ubuntu-server sshd[{400 + index}]: Accepted password for admin from {internal_ip} port {50000 + (index % 1200)} ssh2",
            f"{timestamp} firewall01 kernel: ALLOW IN=eth0 OUT= MAC=00:15:5d:1f:2a:3b SRC={internal_ip} DST={server_ip} LEN=52 PROTO=TCP SPT={51000 + (index % 900)} DPT=443",
            f'{internal_ip} - - [19/May/2026:{hour:02d}:{minute:02d}:{second:02d} +0530] "GET /index.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
        ]
        return "NORMAL", templates[index % len(templates)]

    if bucket < 7:
        templates = [
            f"May 19 {hour:02d}:{minute:02d}:{second:02d} ubuntu-server sshd[{500 + index}]: Failed password for invalid user root from {attacker_ip} port {39000 + (index % 800)} ssh2",
            f"{timestamp} firewall01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:1f:2a:3b SRC={attacker_ip} DST={server_ip} LEN=60 PROTO=TCP SPT={39000 + (index % 900)} DPT=22",
            f'{timestamp} web01 ERROR authentication_failure src_ip={attacker_ip} user=admin message="Multiple failed login attempts detected"',
        ]
        return "SUSPICIOUS", templates[index % len(templates)]

    templates = [
        f'{attacker_ip} - - [19/May/2026:{hour:02d}:{minute:02d}:{second:02d} +0530] "GET /login.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 500 612 "-" "sqlmap/1.8"',
        f"{timestamp} WinEventLog: Security: 4688: Microsoft-Windows-Security-Auditing: New Process Created: Account Name: guest Process Command Line: powershell.exe -EncodedCommand SQBFAFgA",
        f'{timestamp} endpoint-agent CRITICAL file_deleted path="/var/log/auth.log" user="root" src_ip="{server_ip}"',
    ]
    return "ATTACK", templates[index % len(templates)]


def main():
    counts = {"NORMAL": 0, "SUSPICIOUS": 0, "ATTACK": 0}
    lines = []

    for index in range(1, 10001):
        label, line = build_log_line(index)
        counts[label] += 1
        lines.append(line)

    OUTPUT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Created: {OUTPUT_FILE.resolve()}")
    print(f"Total logs: {len(lines)}")
    print(f"Normal: {counts['NORMAL']}")
    print(f"Suspicious: {counts['SUSPICIOUS']}")
    print(f"Attack: {counts['ATTACK']}")


if __name__ == "__main__":
    main()
