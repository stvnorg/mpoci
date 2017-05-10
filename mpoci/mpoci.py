import os
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash

app = Flask(__name__)   # create the application instance :)
app.config.from_object(__name__)    # load config from this file, mpoci.py

#Load default config and override config from an environment variable
app.config.update(dict(
    DATABASE = os.path.join(app.root_path, 'mpoci.db'),
    SECRET_KEY = 'mpoci_development_key',
    USERNAME = 'admin',
    PASSWORD = 'default'
))
app.config.from_envvar('MPOCI_SETTINGS', silent=True)

def connect_db():
    """Connects to the specific database."""
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'mpoci.db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'mpoci.db'):
        g.sqlite_db.close()

""" Initiate SQLite Database """
def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

@app.cli.command('initdb')
def initdb_command():
    """Initializes the database. """
    init_db()
    print('Initialized the database.')
""" initdb END OF FUNCTION """

@app.route('/')
def main_page():
    username = request.cookies.get('username')
    if not username:
        return redirect(url_for('login'))
    else:
        return 'Main Page'

@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None
    user_cookies = request.cookies.get('username')
    if user_cookies:
        return redirect(url_for('main_page'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if error:
            return render_template('login.html', error=error)
        else:
            return redirect(url_for('main_page'))
    else:
        return render_template('login.html', error=error)

@app.route('/new_member', methods=['POST', 'GET'])
def new_member():
    if request.method == 'POST':
        name = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        return ",".join[name,username,password]
    else:
        return render_template('new_member.html')

if __name__ == '__main__':
    app.run()

