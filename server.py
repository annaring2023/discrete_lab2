import socket
import threading
from additions import generate_keys, get_hash, decrypt, encrypt


class Server:
    """A multithreaded chat server implementing RSA encryption and message integrity."""

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.client_keys = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.pub_key, self.priv_key = generate_keys()

    def start(self):
        """Start the server, handle key exchange with new clients, and spawn handler threads."""
        self.s.bind((self.host, self.port))
        self.s.listen(100)
        print(f"Ура, сервер запустився! Публічний ключ: {self.pub_key}")

        while True:
            c, addr = self.s.accept()
            try:
                data = c.recv(1024).decode()
                username, key_part = data.split('|')
                client_pub_key = tuple(map(int, key_part.split(',')))
                print(f"{username} tries to connect")
                self.broadcast(f'new person has joined: {username}')
                self.username_lookup[c] = username
                self.clients.append(c)
                self.client_keys[c] = client_pub_key

                pub_key_str = f"{self.pub_key[0]},{self.pub_key[1]}"
                c.send(pub_key_str.encode())
                secret_token = "SECRET_TOKEN_123"
                h = get_hash(secret_token)
                encrypted_secret = encrypt(secret_token, client_pub_key)
                encrypted_str = ",".join(map(str, encrypted_secret))
                c.send(f"{h}|{encrypted_str}".encode())
                threading.Thread(target=self.handle_client,
                                 args=(c, addr,)).start()
            except Exception:
                print("Помилка")
                c.close()

    def broadcast(self, msg: str):
        """Encrypt and send a message to all currently connected clients."""
        for client in list(self.clients):
            try:
                h = get_hash(msg)
                enc_msg = encrypt(msg, self.client_keys[client])
                full_mesg = f"{h}|{','.join(map(str, enc_msg))}"
                client.send(full_mesg.encode())
            except Exception:
                if client in self.clients:
                    self.clients.remove(client)

    def handle_client(self, c: socket, addr):
        """Listen for incoming client messages, verify integrity, and broadcast decrypted text."""
        while True:
            try:
                data = c.recv(1024).decode()
                if not data:
                    break
                h_recv, enc_str = data.split('|')
                enc_nums = list(map(int, enc_str.split(',')))
                decrypted_msg = decrypt(enc_nums, self.priv_key)

                if get_hash(decrypted_msg) == h_recv:
                    full_msg = f"{self.username_lookup[c]}: {decrypted_msg}"
                    self.broadcast(full_msg)
                else:
                    print(
                        f"О нііі, повідомлення від {addr} змінено або пошкоджено!")
            except Exception:
                break


if __name__ == "__main__":
    s = Server(9001)
    s.start()
