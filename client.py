import socket
import threading
from additions import generate_keys, get_hash, decrypt, encrypt


class Client:
    """A secure chat client with RSA encryption and SHA-256 integrity verification."""

    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.pub_key, self.priv_key = generate_keys()
        self.server_pub_key = None

    def init_connection(self):
        """Establish server connection and perform initial public key exchange."""
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print(f"{self.username}: could not connect to server: ", e)
            return

        key_str = f"{self.pub_key[0]},{self.pub_key[1]}"
        self.s.send(f"{self.username}|{key_str}".encode())
        srv_data = self.s.recv(1024).decode()
        self.server_pub_key = tuple(map(int, srv_data.split(',')))

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        """Handle incoming data: receive, decrypt, and verify message integrity."""
        while True:
            try:
                data = self.s.recv(4096).decode()
                received_hash, encrypted_str = data.split('|')
                encrypted_numbers = list(map(int, encrypted_str.split(',')))
                message = decrypt(encrypted_numbers, self.priv_key)
                if get_hash(message) == received_hash:
                    print(message)
            except Exception:
                break

    def write_handler(self):
        """Process user input: hash, encrypt, and send messages to the server."""
        while True:
            message = input()
            h = get_hash(message)
            enc_msg = encrypt(message, self.server_pub_key)
            full_mesg = f"{h}|{','.join(map(str, enc_msg))}"
            self.s.send(full_mesg.encode())


if __name__ == "__main__":
    name = input("Введіть ваше ім'я: ")
    cl = Client("127.0.0.1", 9001, name)
    cl.init_connection()
