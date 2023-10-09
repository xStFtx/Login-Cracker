import argparse
import itertools
import multiprocessing
import socks
import socket
import threading
import logging
import sys
import random
import string
import time

DEFAULT_NUM_THREADS = 5
DEFAULT_PASSWORD_LENGTH = 5
DEFAULT_NUM_PROCESSES = 4
DEFAULT_EXIT_ON_FIRST_MATCH = True
DEFAULT_LOGGING_LEVEL = logging.INFO

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
parser.add_argument("--exit-on-first-match", action="store_true", help="Exit on first valid login match")
parser.add_argument("--log-file", default="login_cracker.log", help="Log file path")
parser.add_argument("--log-level", default=DEFAULT_LOGGING_LEVEL, help="Logging level")
parser.add_argument("--attack-mode", choices=["dictionary", "hybrid", "bruteforce"], default="bruteforce",
                    help="Password cracking mode (dictionary, hybrid, bruteforce)")
parser.add_argument("--dictionary-file", help="Path to the dictionary file for dictionary and hybrid attacks")

args = parser.parse_args()

TARGET_HOST = args.host
TARGET_PORT = args.port
exit_event = multiprocessing.Event()

logging.basicConfig(
    filename=args.log_file,
    level=args.log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

def socks_proxy_thread(target_host, target_port):
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
        exit_event.set()

def is_valid_login(username, password):
    return username == args.username and password == args.password

def dictionary_attack(username, dictionary_file):
    with open(dictionary_file, 'r') as file:
        for password in file.readlines():
            password = password.strip()
            if is_valid_login(username, password):
                return username, password
    return None

def hybrid_attack(username, dictionary_file, charset, password_length, result_queue):
    dictionary_result = dictionary_attack(username, dictionary_file)
    if dictionary_result:
        result_queue.put(dictionary_result)
        if args.exit_on_first_match:
            exit_event.set()
    else:
        brute_force_result = brute_force_attack(username, charset, password_length)
        if brute_force_result:
            result_queue.put(brute_force_result)
            if args.exit_on_first_match:
                exit_event.set()

def brute_force_attack(username, charset, password_length):
    possibilities = itertools.product(charset, repeat=password_length)
    for candidate in possibilities:
        if exit_event.is_set():
            return None
        candidate_password = ''.join(candidate)
        if is_valid_login(username, candidate_password):
            return username, candidate_password
    return None

if __name__ == "__main__":
    custom_charset = args.charset

    threads = []
    for _ in range(args.threads):
        thread = threading.Thread(target=socks_proxy_thread, args=(TARGET_HOST, TARGET_PORT))
        threads.append(thread)
        thread.start()

    try:
        for thread in threads:
            thread.join()

        start_time = time.time()

        if args.attack_mode == 'dictionary':
            result = dictionary_attack(args.username, args.dictionary_file)
        elif args.attack_mode == 'hybrid':
            result = hybrid_attack(args.username, args.dictionary_file, custom_charset, args.password_length, result_queue)
        elif args.attack_mode == 'bruteforce':
            result = brute_force_attack(args.username, custom_charset, args.password_length)
        else:
            print("Invalid attack mode. Please use 'dictionary', 'hybrid', or 'bruteforce'.")
            sys.exit(1)

        end_time = time.time()

        if result:
            print(f"Login cracked - Username: {result[0]}, Password: {result[1]}")
        else:
            print("Login not found.")

        execution_time = end_time - start_time
        print(f"Execution time: {execution_time:.2f} seconds")

    except KeyboardInterrupt:
        logging.info("Received KeyboardInterrupt. Exiting gracefully...")
        exit_event.set()
        sys.exit(0)
if __name__ == "__main__":
    custom_charset = args.charset

    threads = []
    for _ in range(args.threads):
        thread = threading.Thread(target=socks_proxy_thread, args=(TARGET_HOST, TARGET_PORT))
        threads.append(thread)
        thread.start()

    try:
        for thread in threads:
            thread.join()

        start_time = time.time()

        if args.attack_mode == 'dictionary':
            result = dictionary_attack(args.username, args.dictionary_file)
        elif args.attack_mode == 'hybrid':
            result = hybrid_attack(args.username, args.dictionary_file, custom_charset, args.password_length, result_queue)
        elif args.attack_mode == 'bruteforce':
            result = brute_force_attack(args.username, custom_charset, args.password_length)
        else:
            print("Invalid attack mode. Please use 'dictionary', 'hybrid', or 'bruteforce'.")
            sys.exit(1)

        end_time = time.time()

        if result:
            print(f"Login cracked - Username: {result[0]}, Password: {result[1]}")
        else:
            print("Login not found.")

        execution_time = end_time - start_time
        print(f"Execution time: {execution_time:.2f} seconds")

    except KeyboardInterrupt:
        logging.info("Received KeyboardInterrupt. Exiting gracefully...")
        exit_event.set()
        sys.exit(0)
