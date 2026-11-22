
from bruteforce_detector import parse_failed, parse_accepted, parse_timestamp


assert parse_failed("hello") is None, "parse_failed should return None for lines that don't match the regex"
assert parse_failed("Failed password for invalid user root from 192.168.1.1 port 22") == ("root", "192.168.1.1", "22"), "parse_failed should return the correct groups for matching lines"
assert parse_failed("Accepted publickey for developer from 172.16.0.44 port 51400") is None, "parse_failed should return None for lines that don't match the regex"

assert parse_accepted("Accepted publickey for developer from 172.16.0.44 port 51400 ssh2: RSA SHA256:d8kLm2") == ("developer", "172.16.0.44", "51400"), "parse_accepted should return the correct groups for matching lines"
assert parse_accepted("Failed password for invalid user root from 192.168.1.1 port 22") is None, "parse_accepted should return None for lines that don't match the regex"

assert parse_timestamp("Jan  1 12:34:56 server sshd[12345]: Failed password for invalid user root from 192.168.1.1 port 22") == "Jan  1 12:34:56", "parse_timestamp should return the correct syslog timestamp for matching lines"
assert parse_timestamp("2024-01-01T12:34:56 server sshd[12345]: Accepted publickey for developer from 172.16.0.44 port 51400") == "2024-01-01T12:34:56", "parse_timestamp should return the correct ISO timestamp for matching lines"