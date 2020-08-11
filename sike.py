from scapy.all import ARP, Ether, srp, arping
import json

maclookup = {}

with open("MACLookup.json", "r") as read_file:
        maclookup = json.load(read_file)

"""
target_ip = "192.168.0.1/24"
# IP Address for the destination
# create ARP packet
arp = ARP(pdst=target_ip)
# create the Ether broadcast packet
# ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
# stack them
packet = ether/arp

result = srp(packet, timeout=3, verbose=0)[0]

# a list of clients, we will fill this in the upcoming loop
clients = []

for sent, received in result:
    # for each response, append ip and mac address to `clients` list
    clients.append({'ip': received.psrc, 'mac': maclookup.get(received.hwsrc, received.hwsrc)})

# print clients
print("Available devices in the network:")
print("IP" + " "*18+"MAC")
for client in clients:
    print("{:16}    {}".format(client['ip'], client['mac']))
"""

things = []
ans,unans = arping("192.168.0.1/24", verbose=0)
for s,r in ans:
	mac = r[Ether].src
	if not mac in things:
		things.append(mac)
    #print("{} {}".format(r[Ether].src,s[ARP].pdst))

print("Pre processed")
print(things)
things = [maclookup.get(x, x) for x in things]
print("Post processed:")
print(things)
