import argparse
import logging
import sys
import string
import time
import itertools
import bcrypt
import multiprocessing
import signal

# Constants
DEFAULT_NUM_PROCESSES = 4
DEFAULT_PASSWORD_MIN_LENGTH = 1
DEFAULT_PASSWORD_MAX_LENGTH = 5
DEFAULT_LOGGING_LEVEL = logging.INFO
DEFAULT_RATE_LIMIT = 1  # in seconds

class LoginCracker:
    def __init__(self, args):
        self.args = args
        if self.args.attack_mode in ["dictionary", "hybrid"] and not self.args.dictionary_file:
            raise ValueError("You need to provide a dictionary file for dictionary or hybrid attacks.")
        self.custom_charset = args.charset
        self.init_logging()
        signal.signal(signal.SIGINT, self.signal_handler)
        self.stored_password_hash = bcrypt.hashpw(self.args.password.encode(), bcrypt.gensalt())

    def init_logging(self):
        """Initialize the logging."""
        logging.basicConfig(
            level=self.args.log_level,
            format="%(asctime)s [%(process)d] - %(levelname)s - %(message)s",
            stream=sys.stdout
        )

    def signal_handler(self, signal, frame):
        logging.info("Interrupt received! Shutting down gracefully...")
        raise KeyboardInterrupt

    def is_valid_login(self, password):
        """Check if the given password is valid for the username."""
        return bcrypt.checkpw(password.encode(), self.stored_password_hash)

    def dictionary_attack(self):
        """Attack using a dictionary."""
        try:
            with open(self.args.dictionary_file, 'r') as file:
                for password in file:
                    password = password.strip()
                    time.sleep(self.args.rate_limit)
                    if self.is_valid_login(password):
                        return self.args.username, password
        except Exception as e:
            logging.error(f"Dictionary attack error: {e}")
        return None

    def brute_force_worker(self, chunk):
        """Worker function for brute force attack."""
        for candidate in chunk:
            candidate_password = ''.join(candidate)
            time.sleep(self.args.rate_limit)
            if self.is_valid_login(candidate_password):
                return self.args.username, candidate_password
        return None

    def run_brute_force(self):
        """Run brute force for different lengths using multiprocessing."""
        pool = multiprocessing.Pool(self.args.processes)

        for length in range(self.args.password_min_length, self.args.password_max_length + 1):
            iterable = itertools.product(self.custom_charset, repeat=length)
            chunk_size = len(self.custom_charset) ** length // self.args.processes
            results = pool.imap(self.brute_force_worker, self.chunkify(iterable, chunk_size), chunksize=1)

            for result in results:
                if result:
                    pool.terminate()
                    return result

        pool.close()
        pool.join()
        return None

    @staticmethod
    def chunkify(iterable, chunk_size):
        """Divide the iterable into chunks of size chunk_size."""
        chunk = []
        for item in iterable:
            if len(chunk) < chunk_size:
                chunk.append(item)
            else:
                yield chunk
                chunk = [item]
        if chunk:
            yield chunk

    def run(self):
        """Main execution method."""
        start_time = time.time()

        attack_map = {
            'dictionary': self.dictionary_attack,
            'hybrid': lambda: self.dictionary_attack() or self.run_brute_force(),
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Parallel Login Cracker")

    parser.add_argument("--username", default="admin", help="Target username")
    parser.add_argument("--password", default="12345", help="Target password to crack")
    parser.add_argument("--charset", default=string.ascii_letters + string.digits + string.punctuation,
                        help="Character set for brute force")
    parser.add_argument("--password-min-length", type=int, default=DEFAULT_PASSWORD_MIN_LENGTH, help="Minimum password length for brute force")
    parser.add_argument("--password-max-length", type=int, default=DEFAULT_PASSWORD_MAX_LENGTH, help="Maximum password length for brute force")
    parser.add_argument("--log-level", default=DEFAULT_LOGGING_LEVEL, help="Logging level")
    parser.add_argument("--attack-mode", choices=["dictionary", "hybrid", "bruteforce"], default="bruteforce",
                        help="Password cracking mode (dictionary, hybrid, bruteforce)")
    parser.add_argument("--dictionary-file", help="Path to the dictionary file for dictionary and hybrid attacks")
    parser.add_argument("--processes", type=int, default=DEFAULT_NUM_PROCESSES, help="Number of processes for brute force")
    parser.add_argument("--rate-limit", type=float, default=DEFAULT_RATE_LIMIT, help="Rate limit for login attempts in seconds")

    args = parser.parse_args()

    try:
        login_cracker = LoginCracker(args)
        login_cracker.run()
    except ValueError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
