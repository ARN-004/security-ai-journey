import re
from collections import Counter

FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")
list_of_data = []
user_count = Counter()
ip_count = Counter()
#پاسخ ب :
def parse_failed(line):
    """Return (user, ip, port) for a failed-login line, otherwise None."""

    match = FAILED_RE.search(line)
    if match:
        # user, ip, port = FAILED_RE.search(line).groups()
        # list_of_data.append((user, ip, port))
        # user_count[user] += 1
        # ip_count[ip] += 1
        return match.groups()

    return None

with open("auth-sample.log") as f:
    for line in f:
        parse = parse_failed(line)
        if parse:
            user, ip, port = parse
            list_of_data.append((user, ip, port))
            ip_count[ip] += 1
            user_count[user] += 1

for data in list_of_data:
    print(data)


# dict_of_IP = dict(Counter(ip for _, ip, _ in list_of_data))
# dict_of_user = dict(Counter(user for user, _, _ in list_of_data))

# پاسخ ج :
print (f"third most frequent IP address: {ip_count.most_common(3)} \nand 5th most frequent user: {user_count.most_common(5)}")

print(f"\nthese IP addresses are suspicious: {[ip for ip, count in ip_count.items() if count > 5]}")

# پاسخ د :
with open("auth-sample.log") as f:
    for ip,count in ip_count.items():
        f.seek(0)  # Reset file pointer to the beginning of the file
        if count > 5:
            print(f"\nthese lines are suspicious for {ip}:")
            for line in f:
                if ip in line:
                    print(line.strip())

# پاسخ ه :
assert parse_failed("hello") == None, "parse_failed should return None for lines that don't match the regex"
assert parse_failed("Failed password for invalid user root from 192.168.1.1 port 22") == ("root", "192.168.1.1", "22"), "parse_failed should return the correct groups for matching lines"