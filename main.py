import argparse
import logging
import sys
import string
import time
import itertools
import bcrypt

# Constants
DEFAULT_NUM_THREADS = 5
DEFAULT_PASSWORD_MIN_LENGTH = 1
DEFAULT_PASSWORD_MAX_LENGTH = 5
DEFAULT_LOGGING_LEVEL = logging.INFO


class LoginCracker:
    def __init__(self, args):
        self.args = args
        self.custom_charset = args.charset
        self.init_logging()

    def init_logging(self):
        """Initialize the logging."""
        logging.basicConfig(
            level=self.args.log_level,
            format="%(asctime)s - %(levelname)s - %(message)s",
            stream=sys.stdout
        )

    def is_valid_login(self, username, password):
        """Check if the given login is valid."""
        stored_password_hash = bcrypt.hashpw(self.args.password.encode(), bcrypt.gensalt())
        return username == self.args.username and bcrypt.checkpw(password.encode(), stored_password_hash)

    def dictionary_attack(self):
        """Attack using a dictionary."""
        try:
            with open(self.args.dictionary_file, 'r') as file:
                for password in file:
                    password = password.strip()
                    if self.is_valid_login(self.args.username, password):
                        return self.args.username, password
        except Exception as e:
            logging.error(f"Dictionary attack error: {e}")
        return None

    def brute_force_attack(self, length):
        """Brute force attack using a specified length."""
        for candidate in itertools.product(self.custom_charset, repeat=length):
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
    parser = argparse.ArgumentParser(description="Parallel Login Cracker")

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

    args = parser.parse_args()

    login_cracker = LoginCracker(args)
    login_cracker.run()
