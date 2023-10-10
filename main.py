import argparse
import multiprocessing
import socks
import socket
import threading
import logging
import sys
import string
import time
import concurrent.futures
import itertools
import secrets
import bcrypt

# Constants
DEFAULT_NUM_THREADS = 5
DEFAULT_PASSWORD_MIN_LENGTH = 1
DEFAULT_PASSWORD_MAX_LENGTH = 5
DEFAULT_NUM_PROCESSES = 4
DEFAULT_LOGGING_LEVEL = logging.INFO
PROXY_TIMEOUT = 10


class LoginCracker:
    def __init__(self, args):
        self.args = args
        self.exit_event = multiprocessing.Event()
        self.custom_charset = args.charset
        self.init_logging()

    def init_logging(self):
        """Initialize the logging."""
        logging.basicConfig(
            level=self.args.log_level,
            format="%(asctime)s - %(levelname)s - %(message)s",
            stream=sys.stdout
        )

    def proxy_connect(self, target_host, target_port):
        """Connect using SOCKS proxy."""
        with socks.socksocket(socket.AF_INET, socket.SOCK_STREAM) as proxy_client:
            proxy_client.set_proxy(socks.SOCKS5, "localhost", 1080)
            proxy_client.connect((target_host, target_port))
            proxy_client.send(f"GET / HTTP/1.1\r\nHost: {target_host}\r\n\r\n".encode())
            return proxy_client.recv(4096).decode("utf-8")

    def socks_proxy_thread(self):
        """Run a SOCKS proxy thread."""
        try:
            response = self.proxy_connect(self.args.host, self.args.port)
            logging.info(f"Received from target: {response}")
        except Exception as e:
            logging.error(f"Proxy thread error: {e}")
        finally:
            self.exit_event.set()

    def is_valid_login(self, username, password):
        """Check if the given login is valid."""
        stored_password_hash = bcrypt.hashpw(self.args.password.encode(), bcrypt.gensalt())
        return username == self.args.username and bcrypt.checkpw(password.encode(), stored_password_hash)

    def dictionary_attack(self):
        """Attack using a dictionary."""
        with open(self.args.dictionary_file, 'r') as file:
            for password in file:
                password = password.strip()
                if self.is_valid_login(self.args.username, password):
                    return self.args.username, password
                if self.exit_event.is_set():
                    break
        return None

    def brute_force_attack(self, length):
        """Brute force attack using a specified length."""
        for candidate in itertools.product(self.custom_charset, repeat=length):
            if self.exit_event.is_set():
                break
            candidate_password = ''.join(candidate)
            if self.is_valid_login(self.args.username, candidate_password):
                return self.args.username, candidate_password
        return None

    def run_brute_force(self):
        """Run brute force for different lengths."""
        for length in range(self.args.password_min_length, self.args.password_max_length + 1):
            result = self.brute_force_attack(length)
            if result:
                return result
        return None

    def hybrid_attack(self):
        """Run a hybrid attack of dictionary and brute force."""
        result = self.dictionary_attack()
        if not result:
            result = self.run_brute_force()
        return result

    def run(self):
        """Main execution method."""
        threads = [threading.Thread(target=self.socks_proxy_thread) for _ in range(self.args.threads)]
        for thread in threads:
            thread.start()

        try:
            for thread in threads:
                thread.join()

            start_time = time.time()

            attack_map = {
                'dictionary': self.dictionary_attack,
                'hybrid': self.hybrid_attack,
                'bruteforce': self.run_brute_force
            }

            result = attack_map.get(self.args.attack_mode, lambda: None)()

            end_time = time.time()

            # Output results
            if result:
                print(f"\nLogin cracked - Username: {result[0]}, Password: {result[1]}")
            else:
                print("Login not found.")
            print(f"Execution time: {end_time - start_time:.2f} seconds")

        except KeyboardInterrupt:
            logging.info("Received KeyboardInterrupt. Exiting gracefully...")
            self.exit_event.set()
            sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parallel Login Cracker")

    parser.add_argument("--host", default="example.com", help="Target host")
    parser.add_argument("--port", type=int, default=80, help="Target port")
    parser.add_argument("--username", default="admin", help="Target username")
    parser.add_argument("--password", default="12345", help="Target password to crack")
    parser.add_argument("--charset", default=string.ascii_letters + string.digits + string.punctuation,
                        help="Character set for brute force")
    parser.add_argument("--threads", type=int, default=DEFAULT_NUM_THREADS, help="Number of threads")
    parser.add_argument("--password-min-length", type=int, default=DEFAULT_PASSWORD_MIN_LENGTH, help="Minimum password length for brute force")
    parser.add_argument("--password-max-length", type=int, default=DEFAULT_PASSWORD_MAX_LENGTH, help="Maximum password length for brute force")
    parser.add_argument("--log-level", default=DEFAULT_LOGGING_LEVEL, help="Logging level")
    parser.add_argument("--attack-mode", choices=["dictionary", "hybrid", "bruteforce"], default="bruteforce",
                        help="Password cracking mode (dictionary, hybrid, bruteforce)")
    parser.add_argument("--dictionary-file", help="Path to the dictionary file for dictionary and hybrid attacks")

    args = parser.parse_args()

    login_cracker = LoginCracker(args)
    login_cracker.run()
