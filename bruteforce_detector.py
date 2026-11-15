import re
from collections import Counter

FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")
list_of_data = []
user_count = Counter()
ip_count = Counter()
dict_of_failed_logins_ips = {}

def parse_failed(line):
    """Return (user, ip, port) for a failed-login line, otherwise None."""

    match = FAILED_RE.search(line)
    if match:
        return match.groups()

    return None

line_counter = 0
with open("auth-sample.log") as f:
    for line in f:
        line_counter += 1
        parse = parse_failed(line)
        if parse:
            user, ip, port = parse
            list_of_data.append((user, ip, port))
            ip_count[ip] += 1
            user_count[user] += 1
            dict_of_failed_logins_ips[ip] = line_counter

for data in list_of_data:
    print(data)


print (f"3 frequently used IP address: {ip_count.most_common(3)} \nand 5 High-intent users: {user_count.most_common(5)}")

list_of_suspicious_ips = [ip for ip, count in ip_count.items() if count > 5]
print(f"\nthese IP addresses are suspicious: {list_of_suspicious_ips}")

ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)")
with open("auth-sample.log") as f:
    for ip in list_of_suspicious_ips:
        line_number = dict_of_failed_logins_ips[ip]
        counter = 1
        for line in f:
               if counter <= line_number:
                   counter += 1
                   continue
               # Move the file pointer to the line of the suspicious IP
               if ACCEPTED_RE.search(line) and ip in line:
                   print(f"\nthese lines are suspicious for {ip}:")
                   print(line.strip())
        f.seek(0)


assert parse_failed("hello") is None, "parse_failed should return None for lines that don't match the regex"
assert parse_failed("Failed password for invalid user root from 192.168.1.1 port 22") == ("root", "192.168.1.1", "22"), "parse_failed should return the correct groups for matching lines"
assert parse_failed("Accepted publickey for developer from 172.16.0.44 port 51400") is None, "parse_failed should return None for lines that don't match the regex"