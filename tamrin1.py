phrase = "Failed password"
list_of_IP = []
count = 0
with open("auth-sample.log") as f:
    for line in f:
        if phrase in line:
            for split_line in line.split():

                #First solution:
                # if split_line.count(".") == 3 and split_line.replace(".", "").isdigit():
                    # list_of_IP.append(split_line)
                    #break

                #Second solution:
                if split_line == "from":
                    list_of_IP.append(line.split()[line.split().index(split_line) + 1])
                    break
                
            count += 1

dict_of_IP = {ip: list_of_IP.count(ip) for ip in set(list_of_IP)}

print(f"Total occurrences of '{phrase}': {count}")
print("IP addresses with failed password attempts:")
for ip, frequency in dict_of_IP.items():
    print(f"  {ip}: {frequency}")

dict_of_IP_sorted = dict(sorted(dict_of_IP.items(), key=lambda item: item[1], reverse=True))
print("\nJust the 3 most frequent IP addresses:")
for ip, frequency in list(dict_of_IP_sorted.items())[:3]:
    print(f"  {ip}: {frequency}")