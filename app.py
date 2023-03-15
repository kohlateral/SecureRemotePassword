from flask import Flask, render_template, redirect, url_for, request, session, make_response
import srp
import sqlite3
import json

app = Flask(__name__)


conn = sqlite3.connect('users.db', check_same_thread=False)
c = conn.cursor()

# Create users table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY, verifier TEXT, salt TEXT)''')

cache = []


# A helper function to get a user's salt and verifier from the database
def get_user(username):
    c.execute('SELECT salt, verifier FROM users WHERE username=?', (username,))
    row = c.fetchone()
    if row:
        salt, verifier = row
    else:
        salt, verifier = None, None
    return salt, verifier


def convert_to_bytes(string):
    string = bytes([int(string[i:i + 2], 16) for i in range(0, len(string), 2)])
    return string


@app.route('/')
def hello_world():  # put application's code here
    return render_template('index.html')


# Route for handling the landing page logic
@app.route('/welcome')
def welcome():
    return render_template('welcome.html')


# Route for handling the login page logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')


@app.route('/challenge', methods=['POST'])
def challenge():
    username = request.form['username']
    user_info = get_user(username)
    print(user_info)
    if user_info[0] is None:
        # User not found
        return render_template('login.html', error='Invalid username or password')

    # Retrieve the user's salt and verifier from the database
    salt, verifier = user_info
    salt = bytes.fromhex(salt)
    verifier = bytes.fromhex(verifier)

    # server computes public ephemeral value B as a challenge value
    svr = srp.Verifier(username, salt, verifier, hash_alg=srp.SHA256)
    s, B = svr.get_challenge()

    # server computes private ephemeral value b and stores it in cache
    b = svr.get_ephemeral_secret()
    cache.append(b)
    print("b: ", b.hex())
    if s is None or B is None:
        return render_template('login.html', error='Invalid username or password')

    # Send salt and public ephemeral value B to the client
    data = {'salt': s.hex(), 'B': B.hex()}
    return json.dumps(data)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        verifier = request.form['verifier']
        salt = request.form['salt']

        # Save the user's salt and verifier to a database or file
        c.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?)", (username, verifier, salt))
        conn.commit()

        # Printing salt and verifier to the console
        print(f'Salt for {username}: {salt}')
        print(f'Verifier for {username}: {verifier}')
        return render_template('register.html')
    if request.method == 'GET':
        return render_template('register.html')


@app.route('/authenticate', methods=['POST'])
def authenticate():
    if request.method == 'POST':
        credentials = request.form['credentials']
        credentials = json.loads(credentials)
        # A is the client's challenge value
        A = credentials['A']

        # M1 is the client's proof of knowledge of the password
        M1 = credentials['M1']
        username = credentials['username']
        print("A: ", A)
        print("M1: ", M1)
        print("username: ", username)

        user_info = get_user(username)
        salt, verifier = user_info
        salt = bytes.fromhex(salt)
        verifier = bytes.fromhex(verifier)
        A = convert_to_bytes(A)
        M1 = convert_to_bytes(M1)
        b = cache[0]
        svr = srp.Verifier(username, salt, verifier, A, hash_alg=srp.SHA256, bytes_b=b)
        HAMK = svr.verify_session(M1, A)
        print("HAMK: ", HAMK)
        return render_template('welcome.html')


@app.route('/logout')
def logout():
    # session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run()
