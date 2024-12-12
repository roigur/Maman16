import socket
import threading

class Client:
    def __init__(self, host='127.0.0.1', port=12345):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        self.phone_number = self.client_socket.recv(1024).decode()
        print(self.phone_number)
        self.listener_thread = threading.Thread(target=self.listen_for_messages)
        self.listener_thread.start()

    def send_message(self, message):
        self.client_socket.send(message.encode())

    def send_to_client(self, target_phone, message):
        self.client_socket.send(f"SENDTO {target_phone} {message}".encode())

    def listen_for_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode()
                if message:
                    print(f"Received: {message}")
            except:
                break

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