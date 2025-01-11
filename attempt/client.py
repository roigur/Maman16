import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import threading
import uuid
import queue
import json


class Client:
    def __init__(self, id):
        self.public_key = b''
        self.keys_file = f'client_keys_{id}.json'

    def save_keys(self, client_id, private_key, public_key):
        """Save keys to a file"""
        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Store in JSON file
        keys_data = {
            'client_id': client_id,
            'private_key': private_pem.decode('utf-8'),
            'public_key': public_pem.decode('utf-8')
        }

        with open(self.keys_file, 'w') as f:
            json.dump(keys_data, f)

    def load_keys(self):
        """Load keys from file if they exist"""
        try:
            with open(self.keys_file, 'r') as f:
                keys_data = json.load(f)

            # Load the private key
            private_key = serialization.load_pem_private_key(
                keys_data['private_key'].encode('utf-8'),
                password=None
            )

            # Load the public key
            public_key = serialization.load_pem_public_key(
                keys_data['public_key'].encode('utf-8')
            )

            return keys_data['client_id'], private_key, public_key
        except (FileNotFoundError, json.JSONDecodeError):
            return None, None, None



    # This function listens for messages from the server
    def receive_messages(self, client_socket, private_key, message_queue):
        while True:
            try:
                message = client_socket.recv(16)
                if message.split(b'\n', 1)[0] in b'-----BEGIN PUBLIC KEY-----':
                    self.public_key = b'-----BEGIN PUBLIC KEY-----' + client_socket.recv(4080).split(b'\n', 1)[1]
                    print(f"Got public key \n {self.public_key}")
                else:
                    # Extract sender ID
                    sender_id = message[:16].decode().strip()
                    msg_size = client_socket.recv(4)
                    encrypted_message = b''  # Start with an empty message
                    remaining = int.from_bytes(msg_size, 'big')  # How many more bytes to read

                    # Read the entire message in chunks
                    while remaining > 0:
                        chunk = client_socket.recv(min(remaining, 1024))
                        if not chunk:
                            break
                        encrypted_message += chunk
                        remaining -= len(chunk)

                    # Decrypt the message using our private key
                    message = private_key.decrypt(
                        encrypted_message,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    ).decode()
                    if message == "message received successfully":
                        print(f"Message to {sender_id} was received")
                    else:
                        print(f"Message from {sender_id}: {message}")  # Print the message

                        # Put the message in the queue
                        message_queue.put(f"Message from {sender_id}: {message}")

                        thread = threading.Thread(target=self.send_ok,
                                                  args=(client_socket, sender_id))
                        thread.start()


            except Exception as e:
                print(f"Error receiving message: {e}")  # Print errors if something goes wrong
                break

    # This function requests the public key of another client
    def request_public_key(self, client_socket, target_id):
        try:
            client_socket.send(b"KEYR")  # Send a request for the public key
            client_socket.send(target_id.encode().ljust(16))  # Send the target's ID
            while True:
                if self.public_key != b'':
                    target_public_key = serialization.load_pem_public_key(self.public_key)
                    #print(f"Successfully fetched public key for client {target_id}.")
                    return target_public_key
        except Exception as e:
            print(f"Error requesting public key: {e}")  # Print any errors
            return None

    # Function to send messages (called by main thread)
    def send_message(self, client_socket, target_id, message, recipient_public_key):
        try:
            # Encrypt the message using the target's public key
            encrypted_message = recipient_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.public_key = b''

            # Send the encrypted message and its size to the server
            msg_size = len(encrypted_message).to_bytes(4, 'big')
            client_socket.send(b"SEND")
            client_socket.send(target_id.encode().ljust(16))
            client_socket.send(msg_size)  # Send the size first
            client_socket.send(encrypted_message)  # Then send the message
        except Exception as e:
            print(f"Error sending message: {e}")  # Print any errors

    def send_ok(self, client_socket, sender_id):
        recipient_public_key = self.request_public_key(client_socket, sender_id)
        self.send_message(client_socket, sender_id, "message received successfully", recipient_public_key)

    # The main function that runs the client
    def start(self,start_id):
        server_address = ("127.0.0.1", 12345)

        # Try to load existing keys
        client_id, private_key, public_key = self.load_keys()
        client_id = start_id
        # If no existing keys, generate new ones and get client ID
        if not private_key:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
            print(f"created private key: {private_key} \n and public key: {public_key}")
            # Save the new keys
            self.save_keys(client_id, private_key, public_key)
        else:
            print(f"Loaded existing keys for client ID: {client_id} : \n {private_key} , \n {public_key}")

        # Connect to the server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(server_address)

        # Send client ID to server
        client_socket.send(client_id.encode().ljust(16))

        # Send the client's public key to the server
        client_public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.send(client_public_key_pem)

        # Receive and verify the verification code
        verification_code = client_socket.recv(6).decode()
        print(f"Received verification code: {verification_code}")
        user_code = input("Enter the verification code: ")
        client_socket.send(user_code.encode())

        # Create message queue and start receive thread
        message_queue = queue.Queue()
        thread = threading.Thread(target=self.receive_messages, args=(client_socket, private_key, message_queue))
        thread.start()

        while True:
            try:
                # Check for new messages in the queue (non-blocking)
                try:
                    while not message_queue.empty():
                        print(message_queue.get())
                except queue.Empty:
                    pass

                # Ask the user for a target client ID and a message
                target_id = input("Enter target client ID: ")
                if target_id.lower() == "exit":
                    break
                message = input("Enter message: ")
                if message.lower() == "exit":
                    break

                # Get the target's public key
                recipient_public_key = self.request_public_key(client_socket, target_id)
                if not recipient_public_key:
                    continue

                # Send the message
                self.send_message(client_socket, target_id, message, recipient_public_key)


            except Exception as e:
                print(f"Error: {e}")  # Print any errors
                break

        client_socket.close()

if __name__ == "__main__":
    while True:
        client_id = str(input("Enter client ID (it needs to be 4 characters long): "))
        if len(client_id) == 4:
            break
    client = Client(client_id)  # Run the client
    client.start(client_id)
