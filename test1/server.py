import socket
import threading

class ClientHandler(threading.Thread):
    def __init__(self, server, client_socket, client_address, phone_number):
        threading.Thread.__init__(self)
        self.server = server
        self.client_socket = client_socket
        self.client_address = client_address
        self.phone_number = phone_number

    def run(self):
        print(f"Client {self.phone_number} connected from {self.client_address}")
        self.client_socket.send(f"Your phone number is: {self.phone_number}".encode())
        while True:
            try:
                message = self.client_socket.recv(1024).decode()
                if not message:
                    break
                print(f"Received from {self.phone_number}: {message}")
                if message.startswith("SENDTO"):
                    _, target_phone, msg = message.split(" ", 2)
                    self.server.send_to_client(self.phone_number, target_phone, msg)
                else:
                    self.client_socket.send(f"Echo: {message}".encode())
            except:
                break
        print(f"Client {self.phone_number} disconnected")
        self.client_socket.close()

class Server:
    def __init__(self, host='0.0.0.0', port=12345):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)
        self.clients = {}

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
                self.clients[phone_number] = client_handler
                client_handler.start()

    def send_to_client(self, sender_phone, target_phone, message):
        if target_phone in self.clients:
            self.clients[target_phone].client_socket.send(f"Message from {sender_phone}: {message}".encode())
        else:
            print(f"Client with phone number {target_phone} not found")

if __name__ == "__main__":
    server = Server()
    server.start()