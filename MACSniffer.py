from scapy.all import ARP, Ether, srp
import datetime
import time
import json
import pygsheets
from threading import Timer
import csv


"""
TODO
* Check row before overwriting it
* Populate MACLookup
* Test range
* Add date
* Test network range

"""


class RepeatTimer(Timer):
    def run(self):
        while not self.finished.wait(self.interval):
            self.function(*self.args, **self.kwargs)


def scanAddresses():
        global packet, MACTable, sessions, MACwhitelist

        result = srp(packet, timeout=3, verbose=0)[0]

        # a list of clients, we will fill this in the upcoming loop
        clients = []

        for sent, received in result: 
                # for each response, mac address to 'clients' list
                if received.hwsrc not in MACwhitelist and received.hwsrc not in clients:
                        clients.append(received.hwsrc)

        tempMacList = list(MACTable.keys())
        tempMacList.remove('lastRow')

        try:
                tempMacList.remove('sessions')
        except ValueError:
                pass

        for mac in clients:
                if mac in MACTable.keys(): 
                        tempMacList.remove(mac)
                        MACTable[mac][1] = 0
                else:
                        MACTable[mac] = [str(datetime.datetime.now())[11:19], 0]

        for mac in tempMacList:
                if MACTable[mac][1] > 11:
                        sessions.append((mac, MACTable[mac][0], str(datetime.datetime.now())[11:19]))
                        del MACTable[mac]
                else:
                        MACTable[mac][1] += 1

def uploadData():

        global sessions, MACTable, lookup, gc

        MACTable["sessions"] = sessions

        currentRow = MACTable["lastRow"]

        sheet = gc.open('Attendance')
        wks = sheet[0]

        #TESTING
        print(MACTable)
        """
        DONT BE STUPID AND FORGET TO FIX THE SESSIONS LOOP ERROR 
        WHEN CELL IS NON-EMPTY
        """

        offset = False

        for i in MACTable["sessions"]:
                while wks.get_value("A{}".format(currentRow)) != "":
                        currentRow += 1
                        offset = True
                while wks.get_value("A{}".format(currentRow - 1)) == "":
                        currentRow -= 1
                        offset = True
                values = [[lookup.get(i[0], i[0]), 
                                            i[1], 
                                            i[2], 
                                            '=C{0}-B{0}'.format(str(currentRow)), 
                                            '=index(split(D{0},":"),1)*60+index(split(D{0},":"),2)'.format(str(currentRow))]]
                #CSV STUFF
                values[0][3] = int(values[0][1].split(":")[1]) * 60 + 
                values[0][4]
                csvwriter.writerow(values[0])


                if offset:
                        values[0].append("Offset Row")
                        offset = False

                wks.update_row(currentRow, values)
                currentRow += 1
        MACTable["sessions"] = []
        sessions = []

        MACTable["lastRow"] = currentRow

print("Program started")
file = open("control", "w+")
file.write("0")
MACwhitelist = ["cc:40:d0:c2:5c:a2"]
MACTable = {}
sessions = [] #Tuples of MAC, start, end

tempData = {}
with open("data.json", "r") as read_file:
        tempData = json.load(read_file)

MACTable["lastRow"] = tempData.get("lastRow", 0)

lookup = {}

target_ip = "192.168.0.1/24"
#IP Address for the destination
# create ARP packet

arp = ARP(pdst=target_ip)
# create the Ether broadcast packet
# ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
# stack them
packet = ether/arp

with open("MACLookup.json", "r") as read_file:
        lookup = json.load(read_file)


gc = pygsheets.authorize(service_file="gsCreds.json")

monitorTimer = RepeatTimer(5, scanAddresses)
uploadTimer = RepeatTimer(30, uploadData)

monitorTimer.start()
uploadTimer.start()

csvfile = open('log.csv', 'w', newline='')
csvwriter = csv.writer(csvfile)

run = True
print("Starting scan routine")
while run:
        time.sleep(10)
        
        file.seek(0)
        control_flag = file.read().strip("\n")
        
        if control_flag != "0":
                run = False
                print("Shutting down...")

        
        # print clients
        #print("Available devices in the network:")
        #print("IP" + " "*20 + "MAC")
        #for client in clients:
                #print("{:16}	{}".format(client['ip'], client['mac']))
                
file.close()
csvfile.close()
monitorTimer.cancel()
uploadTimer.cancel()

with open("data.json", "w") as write_file:
        json.dump(MACTable, write_file)
