from scapy.all import ARP, Ether, srp
import datetime
import time

file = open("control", "w+")
file.write("0")
MACwhitelist = ["cc:40:d0:c2:5c:a2"]
MACTable = {}
sessions = [] #Tuples of MAC, start, end

run = True
while run:
        time.sleep(5)
        
        file.seek(0)
        control_flag = file.read().strip("\n")
        
        if control_flag != "0":
                run = False

        target_ip = "192.168.0.1/24"
        #IP Address for the destination
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
                # for each response, mac address to 'clients' list
                if received.hwsrc not in MACwhitelist and received.hwsrc not in clients:
                        clients.append(received.hwsrc)

        tempMacList = list(MACTable.keys())
        for mac in clients:
                if mac in MACTable.keys(): 
                        tempMacList.remove(mac)
                        MACTable[mac][1] = 0
                else:
                        MACTable[mac] = [str(datetime.datetime.now())[11:19], 0]
        for mac in tempMacList:
                if MACTable[mac][1] > 11:
                        sessions.append((mac, MACTable.get(mac), str(datetime.datetime.now())[11:19]))
                        del MACTable[mac]
                else:
                        MACTable[mac][1] += 1
        # print clients
        #print("Available devices in the network:")
        #print("IP" + " "*20 + "MAC")
        #for client in clients:
                #print("{:16}	{}".format(client['ip'], client['mac']))
                
file.close()
print(sessions)
print(MACTable)
