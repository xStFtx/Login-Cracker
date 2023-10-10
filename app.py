from flask import Flask, render_template, request, redirect, url_for, session, flash
import argparse
import threading
from main import LoginCracker

app = Flask(__name__, template_folder="templates", static_folder="public")

app.secret_key = 'some_secret_key'  # for session management

# Storage for results (you might want to use a database in a real-world scenario)
RESULTS = {}

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        form_data = {
            "host": request.form["host"],
            "port": int(request.form["port"]),
            "username": request.form["username"],
            "password": request.form["password"],
            "charset": request.form["charset"],
            "threads": int(request.form["threads"]),
            "processes": int(request.form["processes"]),
            "password_length": int(request.form["password_length"]),
            "exit_on_first_match": bool(request.form.get("exit_on_first_match")),
            "attack_mode": request.form["attack_mode"],
        }

        if form_data["attack_mode"] in ["hybrid", "dict"]:
            form_data["dictionary_file"] = request.form["dictionary_file"]
        else:
            form_data["dictionary_file"] = None

        # Run in the background
        thread = threading.Thread(target=run_cracker, args=(form_data,))
        thread.start()

        # Store thread in session for retrieval
        session['task_id'] = thread.ident
        flash("Cracking process started! Check back later for results.")

        return redirect(url_for('index'))

    return render_template("index.html")

def run_cracker(form_data):
    args = argparse.Namespace(**form_data)
    login_cracker = LoginCracker(args)
    result = login_cracker.run()
    RESULTS[session['task_id']] = result

@app.route("/results/")
def results():
    task_id = session.get('task_id')
    result = RESULTS.get(task_id)

    if not result:
        return "No results yet. Please check back later."

    return f"Cracked credentials: Username: {result[0]}, Password: {result[1]}"

if __name__ == "__main__":
    app.run(debug=True)
