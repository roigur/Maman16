import socket
import threading
from cryptography.hazmat.primitives import serialization

# A "phonebook" to keep track of all clients and their information
phonebook = {}

# This function handles communication with a single client
def handle_client(client_socket, client_id):
    try:
        # Keep talking to the client until something goes wrong
        while True:
            # Wait for a command from the client (it will be a short word like "KEYR" or "SEND")
            command = client_socket.recv(4).decode()

            # If the client wants a public key (KEYR), we find the public key and send it
            if command == "KEYR":
                target_id = client_socket.recv(16).decode().strip()  # Get the client's ID
                if target_id in phonebook:  # If the target is in the phonebook
                    public_key_data = phonebook[target_id]["public_key"]
                    client_socket.send(public_key_data)  # Send the public key
                else:
                    client_socket.send(b"")  # If the target isn't in the phonebook, send nothing

            # If the client wants to send a message (SEND), we send the message to the correct person
            elif command == "SEND":
                target_id = client_socket.recv(16).decode().strip()  # Get the target's ID
                msg_size = client_socket.recv(4)  # Get the size of the message
                encrypted_message = client_socket.recv(int.from_bytes(msg_size, 'big'))  # Get the encrypted message

                if target_id in phonebook:  # If the target is in the phonebook
                    target_socket = phonebook[target_id]["socket"]
                    target_socket.send(client_id.encode().ljust(16))  # Send the sender's ID
                    target_socket.send(msg_size)  # Send the message size
                    target_socket.send(encrypted_message)  # Send the encrypted message
                else:
                    print(f"Target client {target_id} not found.")  # Print error if target not found
    except Exception as e:
        print(f"Error handling client {client_id}: {e}")  # Print any errors that happen during communication
    finally:
        # Clean up and remove the client from the phonebook when done
        if client_id in phonebook:
            del phonebook[client_id]
        client_socket.close()

# The main function that runs the server
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 12345))  # Listen on all network interfaces, port 12345
    server.listen(5)  # Allow up to 5 clients to connect
    print("Server listening on port 12345")

    while True:
        # Wait for a client to connect
        client_socket, addr = server.accept()
        print(f"Connection from {addr}")  # Print where the client is connecting from

        try:
            # When a client connects, we get their ID and public key
            client_id = client_socket.recv(16).decode().strip()
            client_public_key = client_socket.recv(1024)

            # Add the client to the phonebook
            phonebook[client_id] = {
                "public_key": client_public_key,
                "socket": client_socket
            }
            print(f"Client {client_id} registered.")  # Print confirmation that client is registered

            # Start a new thread to handle messages from this client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_id))
            client_thread.start()
        except Exception as e:
            print(f"Error during client registration: {e}")  # Print errors if there are any
            client_socket.close()

if __name__ == "__main__":
    main()  # Run the server
