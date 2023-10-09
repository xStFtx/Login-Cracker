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

def worker(start, end, charset, password_length, result_queue):
    possibilities = itertools.product(charset, repeat=password_length)
    for candidate in itertools.islice(possibilities, start, end):
        if exit_event.is_set():
            return
        candidate_password = ''.join(candidate)
        if is_valid_login(args.username, candidate_password):
            result_queue.put((args.username, candidate_password))
            if args.exit_on_first_match:
                exit_event.set()

def parallel_brute_force_login(password_length, num_processes, charset):
    chunk_size = len(charset) ** password_length // num_processes
    result_queue = multiprocessing.Queue()

    processes = []
    for i in range(num_processes):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i < num_processes - 1 else len(charset) ** password_length
        process = multiprocessing.Process(target=worker, args=(start, end, charset, password_length, result_queue))
        processes.append(process)

    for process in processes:
        process.start()

    for process in processes:
        process.join()

    cracked_logins = []
    while not result_queue.empty():
        cracked_logins.append(result_queue.get())

    return cracked_logins

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
        cracked_logins = parallel_brute_force_login(args.password_length, args.processes, custom_charset)
        end_time = time.time()

        if cracked_logins:
            print("Cracked logins:")
            for username, password in cracked_logins:
                print(f"Username: {username}, Password: {password}")
        else:
            print("Login not found.")

        execution_time = end_time - start_time
        print(f"Execution time: {execution_time:.2f} seconds")

    except KeyboardInterrupt:
        logging.info("Received KeyboardInterrupt. Exiting gracefully...")
        exit_event.set()
        sys.exit(0)
