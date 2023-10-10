# Login-Cracker 
## !!!Work In Progress !!!
Python Login Cracker 
- Bruteforce
- Dictionary
- Hybrid

## Installation:
```
git clone https://github.com/xStFtx/Login-Cracker.git
cd Login-Cracker
pip install -r requirements.txt
```

## Two ways:
I am making it command line accesible with argparse ```python main.py```(with the args as seen below) or you can use ```python app.py``` to use it on a Flask server.

## Parallel Login Cracker Command-Line Arguments

This section describes the command-line arguments that can be used to configure and run the Parallel Login Cracker.

### Basic Arguments

- `--host`: *(Default: "example.com")* The target host for the login attempt.

- `--port`: *(Default: 80)* The target port for the login attempt.

- `--username`: *(Default: "admin")* The target username for the login attempt.

- `--password`: *(Default: "12345")* The target password to crack.

### Brute Force Configuration

- `--charset`: *(Default: string.ascii_letters + string.digits + string.punctuation)* The character set for brute force attacks. This defines the set of characters that will be used to generate passwords.

- `--threads`: *(Default: 5)* The number of threads to use for the brute force attack.

- `--processes`: *(Default: 4)* The number of processes to use for the brute force attack.

- `--password-length`: *(Default: 5)* The password length for brute force attempts.

- `--exit-on-first-match`: If this flag is present, the program will exit as soon as it finds the first valid login match.

### Logging and Mode Selection

- `--log-level`: *(Default: INFO)* The logging level for the program.

- `--attack-mode`: *(Default: "bruteforce")* The password cracking mode. Available options are "dictionary," "hybrid," and "bruteforce."

### Dictionary Attack Configuration

- `--dictionary-file`: The path to the dictionary file for dictionary and hybrid attacks. This file contains a list of passwords to try.

---

---

**Note: Replace the default values and descriptions with your specific use case and details as needed.**

**Important: Only use this tool for systems and resources that you have legal access to. Unauthorized access or attempts to crack passwords without proper authorization are illegal and unethical. Always adhere to applicable laws and ethical guidelines when using this tool.**

