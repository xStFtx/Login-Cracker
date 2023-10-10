from flask import Flask, render_template, request, redirect, url_for
import argparse
from main import LoginCracker

app = Flask(__name__, template_folder="templates", static_folder="public")

# Define the LoginCracker instance globally
login_cracker = None

@app.route("/", methods=["GET", "POST"])
def index():
    global login_cracker

    if request.method == "POST":
        # Get form data
        host = request.form["host"]
        port = int(request.form["port"])
        username = request.form["username"]
        password = request.form["password"]
        charset = request.form["charset"]
        threads = int(request.form["threads"])
        processes = int(request.form["processes"])
        password_length = int(request.form["password_length"])
        exit_on_first_match = bool(request.form.get("exit_on_first_match"))
        attack_mode = request.form["attack_mode"]
        dictionary_file = request.form["dictionary_file"]

        # Initialize the LoginCracker instance
        args = argparse.Namespace(
            host=host,
            port=port,
            username=username,
            password=password,
            charset=charset,
            threads=threads,
            processes=processes,
            password_length=password_length,
            exit_on_first_match=exit_on_first_match,
            attack_mode=attack_mode,
            dictionary_file=dictionary_file,
        )
        login_cracker = LoginCracker(args)

        # Start the cracking process (you may want to use a background task)
        login_cracker.run()

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
