from threading import Thread, Event
from socket import socket, timeout, SHUT_RDWR
from sys import argv

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

remote_public_key = None
public_key_pem = None
private_key = None


class AESCipher(object):

    def __init__(self, key): 
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class Chat:
    """
    A full duplex chat

    Listens for incoming messages from any address localhost has
    Can try to send messages to a single address:port

    Attributes:
        address (str): send address
        port (int): send port
        server_port (int): server port
        server_socket (socket.socket): server socket
        quit_event (threading.Event): program exit event
        out_thread (OutThread): thread managing outgoing messages
        in_thread (InThread): thread managing incoming messages
    """

    DEFAULT_PORT = 50000
    TIME_OUT = 3

    def __init__(self, address: str, port: int, server_port: int=DEFAULT_PORT, time_out=TIME_OUT):
        """
        Creates a server socket for listening and a pair of threads for managing messages

        Args:
            address (str): send address
            port (int): send port
            server_port (int, optional): server port
            time_out (int, optional): timeout for blocking server socket operations
        """
        self.address = address
        self.port = port
        self.server_port = server_port
        self.server_socket = socket()
        self.server_socket.settimeout(time_out)
        self.server_socket.bind(("", self.server_port))  # empty address string means listening to all addresses
        self.server_socket.listen(1)
        self.quit_event = Event()
        self.out_thread = OutThread(self.quit_event, self.address, self.port)
        self.in_thread = InThread(self.quit_event, self.server_socket)

        global private_key
        global public_key_pem
        private_key = self.generate_rsa_keys()
        public_key_pem = self.serialize_public_key(private_key.public_key())

    def run(self):
        """
        Runs the chat
        Waits for both threads to exit gracefully

        """
        print("Starting chat, type `quit()` to exit")
        self.start()

        if self.out_thread.is_alive():
            self.out_thread.join()
        if self.in_thread.is_alive():
            self.in_thread.join()

        self.stop()
        print("Exited.")

    def start(self):
        """
        Starts both threads

        """
        self.out_thread.start()
        self.in_thread.start()

    def stop(self):
        """
        Closes the server socket
        """
        self.server_socket.close()

    def generate_rsa_keys(self):
        return rsa.generate_private_key(backend=default_backend(),
                                               public_exponent=65537,
                                               key_size=2048)

    def serialize_public_key(self,public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)


class ChatThread(Thread):
    """
    Generic class for managing chat messages

    Extends:
        threading.Thread

    Attributes:
        quit_event (threading.Event): program exit event
        encoding (str): message encoding
    """

    ENCODING = "UTF-8"

    def __init__(self, quit_event: Event, encoding: str=ENCODING):
        """
        Args:
            quit_event (threading.Event): program exit event
            encoding (str, optional): message encoding
        """
        super().__init__()
        self.quit_event = quit_event
        self.encoding = encoding


class OutThread(ChatThread):
    """
    Outgoing messages thread for Chat

    Will cause a grateful exit if user types QUIT_MESSAGE

    Extends:
        ChatThread

    Attributes:
        destination (str, int): tuple for destination address and port
    """

    QUIT_MESSAGE = "quit()"

    def __init__(self, quit_event: Event, address: str, port: int):
        """
        Args:
            quit_event (threading.Event): program exit event
            address (str): messages destination address
            port (int): messages destination port
        """
        super().__init__(quit_event, super().ENCODING)
        self.destination = (address, port)
        self.out_socket = socket()
        try:
            self.out_socket.connect(self.destination)
        except ConnectionError:
            print("Unable to connect to {}:{}".format(self.destination[0], self.destination[1]))

    def run(self):
        """
        Handles outgoing messages

        Reads a user message, tries to send it with a new socket
        Will loop until quit_event is set (graceful exit)
        """

        self.send_public_keys()

        while not self.quit_event.is_set():
            message = input()
            if message == "":
                pass
            elif message == OutThread.QUIT_MESSAGE:
                self.quit_event.set()
                print("Exiting...")
                self.out_socket.shutdown(SHUT_RDWR)
                self.out_socket.close()
            else:
                self.out_socket.sendall(self.encrypt(message.encode(self.encoding)))

    def send_public_keys(self):
        try:         
            global public_key_pem
            out_socket.sendall(public_key_pem)
        except ConnectionError:
            print("Unable to connect to {}:{}".format(self.destination[0], self.destination[1]))
            self.send_public_keys()

    def encrypt(self,message):
        global remote_public_key
        return remote_public_key.encrypt(message,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None))


class InThread(ChatThread):
    """
    Incoming messages thread for Chat

    Extends:
        ChatThread

    Attributes:
        server_sock (socket.socket): listening server socket
    """

    BUFFER_SIZE = 1024  # incoming message buffer size

    def __init__(self, quit_event: Event, server_sock: socket):
        """
        Args:
            quit_event (threading.Event): program exit event
            server_sock (socket.socket): listening server socket
        """
        super().__init__(quit_event)
        self.server_sock = server_sock
        while not self.quit_event.is_set():
            try:
                self.connection, self.origin = self.server_sock.accept()  # Should raise a timeout error after some time
            except timeout:
                pass  # Do nothing on timeout error and restart loop (if quit_event is not set)

    def run(self):
        """
        Handles incoming messages

        Waits for incoming connections and prints incoming messages
        Will loop until quit_event is set (graceful exit)
        """
        self.init_public_key()

        while not self.quit_event.is_set():
            try:           
                message = connection.recv(InThread.BUFFER_SIZE)
                message = self.decrypt(message).decode(self.encoding)
                if message != "":
                    print("Received from {} : {}".format(origin[0], message))
            except timeout:
                pass  # Do nothing on timeout error and restart loop (if quit_event is not set)

    def init_public_key(self):
        try:
            self.connection, self.origin = self.server_sock.accept()
            remote_public_key_pem = connection.recv(InThread.BUFFER_SIZE)
            global remote_public_key
            remote_public_key = load_pem_public_key(remote_public_key_pem, backend=default_backend())
            print("Remote public key successfully loaded")
            self.connection.shutdown(SHUT_RDWR)
            self.connection.close()
        except timeout:
            self.init_public_key()
        except ValueError:
            print("Invalid Public Key received")
            self.quit_event.set()

    def decrypt(self,ciphertext):
        global private_key
        return private_key.decrypt(ciphertext,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None))


"""
Executable
"""


def print_help():
    pass


if len(argv) < 3:
    print_help()
else:
    address_arg = argv[1]
    port_arg = int(argv[2])

    if len(argv) < 4:
        chat = Chat(address_arg, port_arg)
    else:
        server_port_arg = int(argv[3])
        chat = Chat(address_arg, port_arg, server_port_arg)


    chat.run()
