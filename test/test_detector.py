
from .test_detector import parse_failed, parse_accepted, parse_timestamp, analyze, find_suspicious_logins
import pytest

# --- تست‌های parse_failed ---
def test_parse_failed_valid_line():
    '''parse_failed should return the correct groups for matching lines'''
    line = "Failed password for invalid user root from 192.168.1.1 port 22"
    assert parse_failed(line) == ("root", "192.168.1.1", "22")

def test_parse_failed_invalid_line():
    '''parse_failed should return None for lines that don't match the regex'''
    line = "Accepted publickey for developer from 172.16.0.44 port 51400"
    assert parse_failed(line) is None

assert parse_failed("hello") is None, "parse_failed should return None for lines that don't match the regex"

# --- تست‌های parse_accepted ---
def test_parse_accepted_valid_line():
    '''parse_accepted should return the correct groups for matching lines'''
    line = "Accepted publickey for developer from 172.16.0.44 port 51400 ssh2: RSA SHA256:d8kLm2"
    assert parse_accepted(line) == ("developer", "172.16.0.44", "51400")

def test_parse_accepted_invalid_line():
    '''parse_accepted should return None for lines that don't match the regex'''
    line = "Failed password for invalid user root from 192.168.1.1 port 22"
    assert parse_accepted(line) is None

# --- تست‌های parse_timestamp ---
def test_parse_timestamp_iso_format():
    '''parse_timestamp should return the correct ISO timestamp for matching lines'''
    line = "2024-01-01T12:34:56 server sshd[12345]: Accepted publickey for developer from 172.16.0.44 port 51400"
    assert parse_timestamp(line) == "2024-01-01T12:34:56"

def test_parse_timestamp_syslog_format():
    '''parse_timestamp should return the correct syslog timestamp for matching lines'''
    line = "Jan  1 12:34:56 server sshd[12345]: Failed password for invalid user root from 192.168.1.1 port 22"
    assert parse_timestamp(line) == "Jan  1 12:34:56"
    line2 = "Nov 15 11:25:01 vm sshd[1]: x"
    assert parse_timestamp(line2) == "Nov 15 11:25:01"

# --- تست‌های analyze & find_suspicious_logins ---
def test_analyze_accept_login_middle():
    ''''''
    line1 = "Nov  5 10:11:04 server sshd[12001]: Failed password for invalid user admin from 192.168.1.50 port 51234 ssh2"
    line2 = "Nov  5 10:14:50 server sshd[12085]: Failed password for ubuntu from 192.168.1.50 port 52100 ssh2"
    line3 = "Nov  5 10:15:02 server sshd[12091]: Failed password for ubuntu from 192.168.1.50 port 52104 ssh2"
    line4 = "Nov  5 10:31:05 server sshd[12325]: Accepted password for ubuntu from 192.168.1.50 port 55012 ssh2"
    line5 = "Nov  5 10:28:45 server sshd[12301]: Failed password for debian from 192.168.1.50 port 54990 ssh2"
    list_of_lines = [line1, line2, line3, line4, line5]
    threshold = 3
    # assert "192.168.1.50" in analyze(list_of_lines, threashold).list_of_suspicious_ips
    result = analyze(list_of_lines, threshold)
    assert "192.168.1.50" in result.list_of_suspicious_ips
    # assert "192.168.1.50" not in find_suspicious_logins(result.list_of_accepted, result.list_of_failed, result.list_of_suspicious_ips)
    find_result = find_suspicious_logins(result.list_of_accepted, result.list_of_failed, result.list_of_suspicious_ips)
    assert len(find_result) == 1
    event = find_result[0]
    assert "192.168.1.50" == event.ip_addr
    assert "ubuntu" == event.user
    assert 3 == event.counter
    assert event.first_failed_timestamp == "Nov  5 10:11:04"
    assert event.last_failed_timestamp == "Nov  5 10:15:02"

def test_analyze_accept_login_before():
    ''''''
    line1 = "Nov  5 10:31:05 server sshd[12325]: Accepted password for ubuntu from 192.168.1.50 port 55012 ssh2"
    line2 = "Nov  5 10:14:50 server sshd[12085]: Failed password for ubuntu from 192.168.1.50 port 52100 ssh2"
    line3 = "Nov  5 10:15:02 server sshd[12091]: Failed password for ubuntu from 192.168.1.50 port 52104 ssh2"
    line4 = "Nov  5 10:11:04 server sshd[12001]: Failed password for invalid user admin from 192.168.1.50 port 51234 ssh2"
    line5 = "Nov  5 10:28:45 server sshd[12301]: Failed password for debian from 192.168.1.50 port 54990 ssh2"
    list_of_lines = [line1, line2, line3, line4, line5]
    threshold = 3

    result = analyze(list_of_lines, threshold)
    assert "192.168.1.50" in result.list_of_suspicious_ips

    find_result = find_suspicious_logins(result.list_of_accepted, result.list_of_failed, result.list_of_suspicious_ips)
    assert len(find_result) == 0
    
def test_analyze_smalller_than_threshold():
    ''''''
    line4 = "Nov  5 10:11:04 server sshd[12001]: Failed password for invalid user admin from 192.168.1.50 port 51234 ssh2"
    line2 = "Nov  5 10:14:50 server sshd[12085]: Failed password for ubuntu from 192.168.1.50 port 52100 ssh2"
    line3 = "Nov  5 10:15:02 server sshd[12091]: Failed password for ubuntu from 192.168.1.50 port 52104 ssh2"
    line1 = "Nov  5 10:31:05 server sshd[12325]: Accepted password for ubuntu from 192.168.1.50 port 55012 ssh2"
    line5 = "Nov  5 10:28:45 server sshd[12301]: Failed password for debian from 192.168.1.50 port 54990 ssh2"
    list_of_lines = [line1, line2, line3, line4, line5]
    threashold = 5
    assert "192.168.1.50" not in analyze(list_of_lines, threashold).list_of_suspicious_ips

