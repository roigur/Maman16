import socket
import threading
import random
import string
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def generate_verification_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_key_from_code(code):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt_',  # Salt should be securely generated and stored
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(code.encode())

class ClientHandler(threading.Thread):
    def __init__(self, server, client_socket, client_address, phone_number):
        threading.Thread.__init__(self)
        self.server = server
        self.client_socket = client_socket
        self.client_address = client_address
        self.phone_number = phone_number
        self.verification_code = generate_verification_code()
        self.verification_time = time.time()
        self.encryption_key = None

    def run(self):
        print(f"Client {self.phone_number} connected from {self.client_address}")
        self.client_socket.send(f"Verification code: {self.verification_code}".encode())
        while True:
            try:
                message = self.client_socket.recv(1024)
                if not message:
                    break
                if self.encryption_key is None:
                    if message.decode() == self.verification_code and time.time() - self.verification_time < 300:
                        self.encryption_key = generate_key_from_code(self.verification_code)
                        self.server.clients[self.phone_number] = self
                        self.client_socket.send("Verification successful".encode())
                    else:
                        self.client_socket.send("Verification failed".encode())
                        break
                else:
                    decrypted_message = self.decrypt_message(message)
                    if decrypted_message.startswith(b"PUBLICKEY"):
                        public_key = serialization.load_pem_public_key(
                            decrypted_message[len("PUBLICKEY "):],
                            backend=default_backend()
                        )
                        self.server.public_keys[self.phone_number] = public_key
                        print(f"Received public key from {self.phone_number}")
                    elif decrypted_message.startswith(b"REQUESTKEY"):
                        _, target_phone = decrypted_message.decode().split(" ", 1)
                        public_key = self.server.public_keys.get(target_phone)
                        if public_key:
                            pem = public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                            encrypted_pem = self.encrypt_message(pem.decode())
                            self.client_socket.send(encrypted_pem)
                        else:
                            self.client_socket.send(self.encrypt_message("Public key not found"))
                    else:
                        print(f"Received from {self.phone_number}: {decrypted_message.decode()}")
                        if decrypted_message.startswith(b"SENDTO"):
                            _, target_phone, msg = decrypted_message.decode().split(" ", 2)
                            self.server.send_to_client(self.phone_number, target_phone, msg)
                        else:
                            encrypted_message = self.encrypt_message(f"Echo: {decrypted_message.decode()}")
                            self.client_socket.send(encrypted_message)
            except Exception as e:
                print(f"Error: {e}")
                break
        print(f"Client {self.phone_number} disconnected")
        self.client_socket.close()

    def encrypt_message(self, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(message.encode()) + encryptor.finalize()

    def decrypt_message(self, encrypted_message):
        iv = encrypted_message[:16]
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_message[16:]) + decryptor.finalize()

class Server:
    def __init__(self, host='0.0.0.0', port=12345):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)
        self.clients = {}
        self.public_keys = {}

    def start(self):
        print("Server started")
        while True:
            client_socket, client_address = self.server_socket.accept()
            phone_number = input("Enter phone number for the new client: ")
            if phone_number in self.clients:
                print(f"Phone number {phone_number} already exists. Connection refused.")
                client_socket.close()
            else:
                client_handler = ClientHandler(self, client_socket, client_address, phone_number)
                client_handler.start()

    def send_to_client(self, sender_phone, target_phone, message):
        if target_phone in self.clients:
            public_key = self.public_keys.get(target_phone)
            if public_key:
                encrypted_message = public_key.encrypt(
                    message.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                self.clients[target_phone].client_socket.send(encrypted_message)
            else:
                print(f"Public key for client {target_phone} not found")
        else:
            print(f"Client with phone number {target_phone} not found")

class Client:
    def __init__(self, host='127.0.0.1', port=12345):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        self.verification_code = self.client_socket.recv(1024).decode()
        print(f"Received verification code: {self.verification_code}")
        user_code = input("Enter the verification code: ")
        self.client_socket.send(user_code.encode())
        response = self.client_socket.recv(1024).decode()
        if response == "Verification successful":
            self.encryption_key = generate_key_from_code(user_code)
            self.generate_rsa_keys()
            self.send_public_key()
            self.listener_thread = threading.Thread(target=self.listen_for_messages)
            self.listener_thread.start()
        else:
            print("Verification failed")
            self.client_socket.close()

    def generate_rsa_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def send_public_key(self):
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        encrypted_pem = self.encrypt_message(b"PUBLICKEY " + pem)
        self.client_socket.send(encrypted_pem)

    def request_public_key(self, target_phone):
        encrypted_request = self.encrypt_message(f"REQUESTKEY {target_phone}")
        self.client_socket.send(encrypted_request)
        encrypted_response = self.client_socket.recv(1024)
        public_key_pem = self.decrypt_message(encrypted_response)
        return serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    def send_message(self, message):
        encrypted_message = self.encrypt_message(message)
        self.client_socket.send(encrypted_message)

    def send_to_client(self, target_phone, message):
        public_key = self.request_public_key(target_phone)
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_message = self.encrypt_message(f"SENDTO {target_phone} ".encode() + encrypted_message)
        self.client_socket.send(encrypted_message)

    def listen_for_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if encrypted_message:
                    message = self.decrypt_message(encrypted_message)
                    print(f"Received: {message.decode()}")
            except Exception as e:
                print(f"Error: {e}")
                break

    def encrypt_message(self, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(message) + encryptor.finalize()

    def decrypt_message(self, encrypted_message):
        iv = encrypted_message[:16]
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_message[16:]) + decryptor.finalize()