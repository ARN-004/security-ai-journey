import re
from collections import Counter
import argparse

FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")
ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)")
list_of_accepted = []
list_of_failed = []
user_count = Counter()
ip_count = Counter()
# dict_of_first_failed_login_ips = {}

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


def main():
    parser = argparse.ArgumentParser(description="Detect brute-force attacks from auth logs.")
    parser.add_argument("--logfile", default="auth-sample.log", help="Path to the auth log file")
    parser.add_argument("--failed-threshold", type=int, default=5, help="Threshold for failed login attempts to consider an IP suspicious")
    args = parser.parse_args()

    with open(args.logfile) as f:
        for line_number, line in enumerate(f, start=1):
            
            parse_failed_result = parse_failed(line)
            parse_accepted_result = parse_accepted(line)
            if parse_failed_result:
                user, ip, port = parse_failed_result
                list_of_failed.append((user, ip, port, line_number, line.strip()[0:15]))
                ip_count[ip] += 1
                user_count[user] += 1
                # dict_of_first_failed_login_ips[ip] = line_number
            elif parse_accepted_result:
                user, ip, port = parse_accepted_result
                list_of_accepted.append((user, ip, port, line_number, line.strip()[0:15]))


    for data in list_of_failed:
        print(data)


    print (f"Top 3 attacking IPs: {ip_count.most_common(3)} \nand Top 5 targeted usernames: {user_count.most_common(5)}")

    list_of_suspicious_ips = [ip for ip, count in ip_count.items() if count > args.failed_threshold]
    print(f"\nthese IP addresses are suspicious: {list_of_suspicious_ips}")

    IsIPsuspicious = False
    for ip in list_of_suspicious_ips:
        print(f"\nthese lines are suspicious for {ip}:")
        line_number_prev = 0
        for user, ip_addr, port, line_number, timestamp in list_of_accepted :
            if ip == ip_addr:
                for user_failed, ip_failed, port_failed, line_number_failed, timestamp_failed in list_of_failed:
                    if line_number > line_number_failed > line_number_prev and ip == ip_failed:
                        IsIPsuspicious = True
                        print(f"Accepted login for {user} from {ip_addr} at {timestamp} after failed login at {timestamp_failed}")
                        break
                line_number_prev = line_number

    if not IsIPsuspicious:
        print("No suspicious successful logins found.")


if __name__ == "__main__":
    main()         


assert parse_failed("hello") is None, "parse_failed should return None for lines that don't match the regex"
assert parse_failed("Failed password for invalid user root from 192.168.1.1 port 22") == ("root", "192.168.1.1", "22"), "parse_failed should return the correct groups for matching lines"
assert parse_failed("Accepted publickey for developer from 172.16.0.44 port 51400") is None, "parse_failed should return None for lines that don't match the regex"