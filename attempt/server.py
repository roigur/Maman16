import socket
import threading
import random
import string
import time

from cryptography.hazmat.primitives import serialization

# A "phonebook" to keep track of all clients and their information
phonebook = {}
messages_for_afk = {}

# Function to generate a random 6-digit code
def generate_verification_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

# This function handles communication with a single client
def handle_client(client_socket, client_id):
    try:
        # Generate and send a random code to the client
        verification_code = generate_verification_code()
        client_socket.send(verification_code.encode())

        # Start a timer for 5 minutes
        client_socket.settimeout(300)  # Set timeout for 5 minutes

        try:
            # Wait for the client to send back the verification code
            received_code = client_socket.recv(6).decode()
            if received_code != verification_code:
                print(f"Client {client_id} failed verification.")
                client_socket.close()
                return
        except socket.timeout:
            print(f"Client {client_id} did not respond in time.")
            client_socket.close()
            return

        print(f"Client {client_id} passed verification.")

        temp_thread = threading.Thread(target=send_all_messages, args=(client_socket, client_id))
        temp_thread.start()

        # Keep talking to the client until something goes wrong
        while True:
            # Wait for a command from the client (it will be a short word like "KEYR" or "SEND")
            command = client_socket.recv(4).decode()

            # If the client wants a public key (KEYR), we find the public key and send it
            if command == "KEYR":
                target_id = client_socket.recv(16).decode().strip()  # Get the client's ID
                print(f'Client {client_id} requested the public key of {target_id}.')
                if target_id in phonebook:  # If the target is in the phonebook
                    public_key_data = phonebook[target_id]["public_key"]
                    client_socket.send(public_key_data)  # Send the public key
                    print(f'Sent {client_id} the public key of {target_id}.')
                else:
                    client_socket.send(b"")  # If the target isn't in the phonebook, send nothing

            # If the client wants to send a message (SEND), we send the message to the correct person
            elif command == "SEND":
                target_id = client_socket.recv(16).decode().strip()  # Get the target's ID
                msg_size = client_socket.recv(4)  # Get the size of the message
                encrypted_message = client_socket.recv(int.from_bytes(msg_size, 'big'))  # Get the encrypted message

                if target_id in phonebook and phonebook[target_id]["is_online"]:  # If the target is in the phonebook
                    target_socket = phonebook[target_id]["socket"]
                    target_socket.send(client_id.encode().ljust(16))  # Send the sender's ID
                    target_socket.send(msg_size)  # Send the message size
                    target_socket.send(encrypted_message)  # Send the encrypted message
                elif target_id in phonebook and not phonebook[target_id]["is_online"]:
                    messages_for_afk[target_id]['from'] = client_id
                    messages_for_afk[target_id]['msg_size'] = msg_size
                    messages_for_afk[target_id]['encrypted_message'] = encrypted_message
                else:
                    print(f"Target client {target_id} not found.")  # Print error if target not found
    except Exception as e:
        print(f"Error handling client {client_id}: {e}")  # Print any errors that happen during communication
    finally:
        # Clean up and remove the client from the phonebook when done
        if client_id in phonebook:
            phonebook[client_id]["is_online"] = False
        client_socket.close()

def send_all_messages(t_socket, target_id):
    if len(messages_for_afk[target_id]['from']) > 0:
        for i in range(len(messages_for_afk[target_id]['from'])):
            t_socket = phonebook[target_id]["socket"]
            t_socket.send(messages_for_afk[target_id]['from'].encode().ljust(16))  # Send the sender's ID
            t_socket.send(messages_for_afk[target_id]['msg_size'])  # Send the message size
            t_socket.send(messages_for_afk[target_id]['encrypted_message'])  # Send the encrypted message

# The main function that runs the server
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 12345))  # Listen on all network interfaces, port 12345
    server.listen(10)  # Allow up to 10 clients to connect
    print("Server listening on port 12345")

    while True:
        # Wait for a client to connect
        client_socket, addr = server.accept()
        print(f"Connection from {addr}")  # Print where the client is connecting from

        try:
            # When a client connects, we get their ID and public key
            client_id = client_socket.recv(16).decode().strip()
            client_public_key = client_socket.recv(1024)
            if client_id not in phonebook:
                # Add the client to the phonebook
                phonebook[client_id] = {
                    "public_key": client_public_key,
                    "socket": client_socket,
                    "is_online": True
                }
                messages_for_afk[client_id] = {
                    "from": [],
                    "msg_size": [],
                    "encrypted_message": []
                }
                # Start a new thread to handle messages from this client
                client_thread = threading.Thread(target=handle_client, args=(client_socket, client_id))
                client_thread.start()
            else:
                phonebook[client_id]["is_online"] = True
                phonebook[client_id]["socket"] = client_socket
                print(f"Client {client_id} reconnected.")  # Print confirmation that client is registered
                client_thread = threading.Thread(target=handle_client, args=(client_socket, client_id))
                client_thread.start()

        except Exception as e:
            print(f"Error during client registration: {e}")  # Print errors if there are any
            client_socket.close()

if __name__ == "__main__":
    main()  # Run the server
