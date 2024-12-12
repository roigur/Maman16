# import socket
# import threading
#
# class Client:
#     def __init__(self, host='127.0.0.1', port=12345):
#         self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         self.client_socket.connect((host, port))
#         self.phone_number = self.client_socket.recv(1024).decode()
#         print(self.phone_number)
#         self.listener_thread = threading.Thread(target=self.listen_for_messages)
#         self.listener_thread.start()
#
#     def send_message(self, message):
#         self.client_socket.send(message.encode())
#
#     def send_to_client(self, target_phone, message):
#         self.client_socket.send(f"SENDTO {target_phone} {message}".encode())
#
#     def listen_for_messages(self):
#         while True:
#             try:
#                 message = self.client_socket.recv(1024).decode()
#                 if message:
#                     print(f"Received: {message}")
#             except:
#                 break
#
#     def close(self):
#         self.client_socket.close()
#
#     def start(self):
#         try:
#             while True:
#                 message = input("Enter message (or 'SENDTO <phone> <message>' to send to another client): ")
#                 if message.lower() == 'exit':
#                     break
#                 self.send_message(message)
#         finally:
#             self.close()

#2
# import socket
# import threading
# import random
# import string
# import time
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# import os
#
# def generate_key_from_code(code):
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=b'salt_',  # Salt should be securely generated and stored
#         iterations=100000,
#         backend=default_backend()
#     )
#     return kdf.derive(code.encode())
#
# class Client:
#     def __init__(self, host='127.0.0.1', port=12345):
#         self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         self.client_socket.connect((host, port))
#         self.verification_code = self.client_socket.recv(1024).decode()
#         print(f"Received verification code: {self.verification_code}")
#         user_code = input("Enter the verification code: ")
#         self.client_socket.send(user_code.encode())
#         response = self.client_socket.recv(1024).decode()
#         if response == "Verification successful":
#             self.encryption_key = generate_key_from_code(user_code)
#             self.generate_rsa_keys()
#             self.send_public_key()
#             self.listener_thread = threading.Thread(target=self.listen_for_messages)
#             self.listener_thread.start()
#         else:
#             print("Verification failed")
#             self.client_socket.close()
#
#     def generate_rsa_keys(self):
#         self.private_key = rsa.generate_private_key(
#             public_exponent=65537,
#             key_size=2048,
#             backend=default_backend()
#         )
#         self.public_key = self.private_key.public_key()
#
#     def send_public_key(self):
#         pem = self.public_key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         )
#         encrypted_pem = self.encrypt_message(b"PUBLICKEY " + pem)
#         self.client_socket.send(encrypted_pem)
#
#     def request_public_key(self, target_phone):
#         encrypted_request = self.encrypt_message(f"REQUESTKEY {target_phone}")
#         self.client_socket.send(encrypted_request)
#         encrypted_response = self.client_socket.recv(1024)
#         public_key_pem = self.decrypt_message(encrypted_response)
#         return serialization.load_pem_public_key(public_key_pem, backend=default_backend())
#
#     def send_message(self, message):
#         encrypted_message = self.encrypt_message(message)
#         self.client_socket.send(encrypted_message)
#
#     def send_to_client(self, target_phone, message):
#         public_key = self.request_public_key(target_phone)
#         encrypted_message = public_key.encrypt(
#             message.encode(),
#             padding.OAEP(
#                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                 algorithm=hashes.SHA256(),
#                 label=None
#             )
#         )
#         encrypted_message = self.encrypt_message(f"SENDTO {target_phone} ".encode() + encrypted_message)
#         self.client_socket.send(encrypted_message)
#
#     def listen_for_messages(self):
#         while True:
#             try:
#                 encrypted_message = self.client_socket.recv(1024)
#                 if encrypted_message:
#                     message = self.decrypt_message(encrypted_message)
#                     print(f"Received: {message.decode()}")
#             except Exception as e:
#                 print(f"Error: {e}")
#                 break
#
#     def encrypt_message(self, message):
#         iv = os.urandom(16)
#         cipher = Cipher(algorithms.AES(self.encryption_key), modes.CFB(iv), backend=default_backend())
#         encryptor = cipher.encryptor()
#         return iv + encryptor.update(message) + encryptor.finalize()
#
#     def decrypt_message(self, encrypted_message):
#         iv = encrypted_message[:16]
#         cipher = Cipher(algorithms.AES(self.encryption_key), modes.CFB(iv), backend=default_backend())
#         decryptor = cipher.decryptor()
#         return decryptor.update(encrypted_message[16:]) + decryptor.finalize()
#
#     def close(self):
#         self.client_socket.close()
#
#     def start(self):
#         try:
#             while True:
#                 message = input("Enter message (or 'SENDTO <phone> <message>' to send to another client): ")
#                 if message.lower() == 'exit':
#                     break
#                 self.send_message(message)
#         finally:
#             self.close()


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

def generate_key_from_code(code):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt_',  # Salt should be securely generated and stored
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(code.encode())

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
        encrypted_request = self.encrypt_message(f"REQUESTKEY {target_phone}".encode())
        self.client_socket.send(encrypted_request)
        encrypted_response = self.client_socket.recv(4096)
        public_key_pem = self.decrypt_message(encrypted_response)
        return serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    def send_message(self, message):
        encrypted_message = self.encrypt_message(message.encode())
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
        encrypted_message = self.encrypt_message(b"SENDTO " + target_phone.encode() + b" " + encrypted_message)
        self.client_socket.send(encrypted_message)

    def listen_for_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(4096)
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

    def close(self):
        self.client_socket.close()

    def start(self):
        try:
            while True:
                message = input("Enter message (or 'SENDTO <phone> <message>' to send to another client): ")
                if message.lower() == 'exit':
                    break
                self.send_message(message)
        finally:
            self.close()


if __name__ == "__main__":
    client = Client()
    client.start()