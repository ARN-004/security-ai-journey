import re
from collections import Counter, defaultdict, namedtuple
import argparse

FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")
ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)")
TIMESTAMP_RE = re.compile(r"(?:\w{3}( \d{2}|  \d{1}) \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")

LoginAttempt = namedtuple('LoginAttempt', ['user', 'ip', 'port', 'line_number', 'timestamp'])
Analysis_Result = namedtuple('AnalysisResult',['list_of_accepted', 'list_of_failed', 'user_count', 'ip_count', 'list_of_suspicious_ips'])


def parse_failed(line):
    """Return (user, ip, port) for a failed-login line, otherwise None."""

    match = FAILED_RE.search(line)
    if match:
        return match.groups()

    return None

def parse_accepted(line):
    """Return (user, ip, port) for an accepted-login line, otherwise None."""

    match = ACCEPTED_RE.search(line)
    if match:
        return match.groups()

    return None

def parse_timestamp(line):
    """Return timestamp for a line, otherwise None."""

    match = TIMESTAMP_RE.search(line)
    if match:
        return match.group(0)

    return None

def analyze(lines, threshold):
    """Analyze lines from the log file and fill the appropriate lists and counters."""
    list_of_accepted = []
    list_of_failed = []
    user_count = Counter()
    ip_count = Counter()

    for line_number, line in enumerate(lines, start=1):

        parse_failed_result = parse_failed(line)
        parse_accepted_result = parse_accepted(line)

        if parse_failed_result:
            parse_timestamp_result = parse_timestamp(line)
            user, ip, port = parse_failed_result
            event = LoginAttempt(user=user, ip=ip, port=port, line_number=line_number, timestamp=parse_timestamp_result)
            list_of_failed.append(event)
            ip_count[ip] += 1
            user_count[user] += 1

        elif parse_accepted_result:
            parse_timestamp_result = parse_timestamp(line)
            user, ip, port = parse_accepted_result
            event = LoginAttempt(user=user, ip=ip, port=port, line_number=line_number, timestamp=parse_timestamp_result)
            list_of_accepted.append(event)

    list_of_suspicious_ips = [ip for ip, count in ip_count.items() if count >= threshold]

    event_Result = Analysis_Result(list_of_accepted, list_of_failed, user_count, ip_count, list_of_suspicious_ips)
    return event_Result

def find_suspicious_logins(list_of_accepted, list_of_failed, list_of_suspicious_ips):
    """Find suspicious successful logins that occurred after failed logins from the same IP."""
    list_of_suspicious_logins = []
    failed_by_ip = defaultdict(list)
    accepted_by_ip = defaultdict(list)

    for event_failed in list_of_failed:
        failed_by_ip[event_failed.ip].append((event_failed.line_number, event_failed.timestamp))

    for event_accepted in list_of_accepted:
        accepted_by_ip[event_accepted.ip].append(event_accepted)


    for ip in list_of_suspicious_ips:
        line_number_prev = 0
        if ip in accepted_by_ip and ip in failed_by_ip:
            for event_accepted in accepted_by_ip[ip]:
                recent_failures = [(line_number_failed, timestamp_failed) for line_number_failed, timestamp_failed in failed_by_ip[ip] if line_number_prev < line_number_failed < event_accepted.line_number]
                list_of_suspicious_logins.append((event_accepted.user, event_accepted.ip, event_accepted.timestamp, recent_failures[-1][1], recent_failures[0][1], len(recent_failures)))
                break
            line_number_prev = event_accepted.line_number

    return list_of_suspicious_logins

def main():
    parser = argparse.ArgumentParser(description="Detect brute-force attacks from auth logs.")
    parser.add_argument("--logfile", default="auth-sample.log", help="Path to the auth log file")
    parser.add_argument("--failed-threshold", type=int, default=5, help="Threshold for failed login attempts to consider an IP suspicious")
    args = parser.parse_args()

    with open(args.logfile) as f:
        Result = analyze(f, args.failed_threshold)

    for data in Result.list_of_failed:
        print(data)

    print (f"Top 3 attacking IPs: {Result.ip_count.most_common(3)} \nand Top 5 targeted usernames: {Result.user_count.most_common(5)}")

    print(f"\nthese IP addresses are suspicious: {Result.list_of_suspicious_ips}")

    suspicious_logins = find_suspicious_logins(Result.list_of_accepted, Result.list_of_failed, Result.list_of_suspicious_ips)

    if suspicious_logins:
        print("\nSuspicious successful logins after failed attempts:")
        for user, ip_addr, timestamp, last_failed_timestamp, first_failed_timestamp, counter in suspicious_logins:
            print(f"Accepted login for {user} from {ip_addr} at {timestamp} after {counter} failed login(s) sequentially between {first_failed_timestamp} and {last_failed_timestamp}")
    else:
        print("No suspicious successful logins found.")


if __name__ == "__main__":
    main()         