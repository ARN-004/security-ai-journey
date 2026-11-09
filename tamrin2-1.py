ips = ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.3", "10.0.0.1"]
print(len(ips), len(set(ips)))
d = {}
for ip in ips:
    d[ip] = d.get(ip, 0) + 1
print(d)
print([ip for ip in ips if ip != "10.0.0.1"])