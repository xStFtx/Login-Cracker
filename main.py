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

DEFAULT_NUM_THREADS = 5
DEFAULT_PASSWORD_LENGTH = 5
DEFAULT_NUM_PROCESSES = 4
DEFAULT_EXIT_ON_FIRST_MATCH = True
DEFAULT_LOGGING_LEVEL = logging.INFO
PROXY_TIMEOUT = 10 

class LoginCracker:
    def __init__(self, args):
        self.args = args
        self.exit_event = multiprocessing.Event()
        self.custom_charset = args.charset
        self.init_logging()

    def init_logging(self):
        logging.basicConfig(
            level=self.args.log_level,
            format="%(asctime)s - %(levelname)s - %(message)s",
            stream=sys.stdout
        )

    def socks_proxy_thread(self, target_host, target_port):
        try:
            with socks.socksocket(socket.AF_INET, socket.SOCK_STREAM) as proxy_client:
                proxy_client.set_proxy(socks.SOCKS5, "localhost", 1080)
                proxy_client.connect((target_host, target_port))
                proxy_client.send(f"GET / HTTP/1.1\r\nHost: {target_host}\r\n\r\n".encode())
                response = proxy_client.recv(4096)
                print(response.decode("utf-8"))
        except Exception as e:
            logging.error(f"Proxy thread error: {e}")
        finally:
            self.exit_event.set()

    def is_valid_login(self, username, password):
        stored_password_hash = bcrypt.hashpw(self.args.password.encode(), bcrypt.gensalt())
        return username == self.args.username and bcrypt.checkpw(password.encode(), stored_password_hash)

    def dictionary_attack(self):
        with open(self.args.dictionary_file, 'r') as file:
            for password in file:
                password = password.strip()
                if self.is_valid_login(self.args.username, password):
                    return self.args.username, password
        return None

    def brute_force_attack(self, chunk):
        for candidate in chunk:
            if self.exit_event.is_set():
                return None
            candidate_password = ''.join(candidate)
            if self.is_valid_login(self.args.username, candidate_password):
                return self.args.username, candidate_password
        return None

    def parallel_brute_force_attack(self):
        chunk_size = len(self.custom_charset) // self.args.processes
        chunks = [self.custom_charset[i:i+chunk_size] for i in range(0, len(self.custom_charset), chunk_size)]

        with concurrent.futures.ProcessPoolExecutor(max_workers=self.args.processes) as executor:
            results = executor.map(self.brute_force_attack, itertools.product(*chunks))

            for result in results:
                if result:
                    self.exit_event.set()
                    return result

    def hybrid_attack(self):
        result = self.dictionary_attack()
        if result:
            return result
        else:
            return self.parallel_brute_force_attack()

    def track_progress(self, progress):
        sys.stdout.write(f"\rProgress: {progress * 100:.2f}%")
        sys.stdout.flush()

    def run(self):
        threads = []
        for _ in range(self.args.threads):
            thread = threading.Thread(target=self.socks_proxy_thread, args=(self.args.host, self.args.port))
            threads.append(thread)
            thread.start()

        try:
            for thread in threads:
                thread.join()

            start_time = time.time()

            if self.args.attack_mode == 'dictionary':
                result = self.dictionary_attack()
            elif self.args.attack_mode == 'hybrid':
                result = self.hybrid_attack()
            elif self.args.attack_mode == 'bruteforce':
                result = self.parallel_brute_force_attack()
            else:
                print("Invalid attack mode. Please use 'dictionary', 'hybrid', or 'bruteforce'.")
                sys.exit(1)

            end_time = time.time()

            if result:
                print(f"\nLogin cracked - Username: {result[0]}, Password: {result[1]}")
            else:
                print("Login not found.")

            execution_time = end_time - start_time
            print(f"Execution time: {execution_time:.2f} seconds")

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
    parser.add_argument("--processes", type=int, default=DEFAULT_NUM_PROCESSES, help="Number of processes")
    parser.add_argument("--password-length", type=int, default=DEFAULT_PASSWORD_LENGTH, help="Password length")
    parser.add_argument("--exit-on-first-match", action="store_true", help="Exit on the first valid login match")
    parser.add_argument("--log-level", default=DEFAULT_LOGGING_LEVEL, help="Logging level")
    parser.add_argument("--attack-mode", choices=["dictionary", "hybrid", "bruteforce"], default="bruteforce",
                        help="Password cracking mode (dictionary, hybrid, bruteforce)")
    parser.add_argument("--dictionary-file", help="Path to the dictionary file for dictionary and hybrid attacks")

    args = parser.parse_args()

    login_cracker = LoginCracker(args)
    login_cracker.run()
