import os
import shutil
import filecmp
import re
import sqlite3
from Crypto.Cipher import AES
from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = '/var/www/qqdewa.test/html'

app = Flask(__name__)   # create the application instance :)
app.config.from_object(__name__)    # load config from this file, mpoci.py
app.secret_key = '\x9c\xe7\xd3\xbe>\xb3\x85M8\xa3\x93nB\xb3\x17\xa7tA\xae\x9fx\xa5\xf0\xfc'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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

def query_db(query, args=(), one=False):
    db = get_db()
    db.text_factory = str
    cur = db.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

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

"""PASSWORD ENCRYPTION/DECRYPTION FUNCTION"""

def encryptPass(password):
    secret_key = '3dF6htKPLjVoKnze'
    iv = 'wJGqH5sYCSam47cE'
    cipher = AES.new(secret_key,AES.MODE_CBC,iv)
    encoded = cipher.encrypt(password.rjust(32))
    return encoded

def decryptPass(password):
    secret_key = '3dF6htKPLjVoKnze'
    iv = 'wJGqH5sYCSam47cE'
    cipher = AES.new(secret_key,AES.MODE_CBC,iv)
    decoded = cipher.decrypt(password)
    return decoded.strip()

""" END OF LINE """

def checkLogin():
    if len(session):
        if 'username' in session.keys():
            username = session['username']
            access = query_db('select level from members where username=?', [username], one=True)
            return access['level']=='admin'
    return False

@app.route('/')
def main_page():
    if len(session):
        if 'username' in session.keys():
            username = session['username']
            return 'Hi ' + username
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None

    if request.method == 'POST':
        username = (request.form['username']).lower()
        password = request.form['password']
        user = query_db("select username,password,level from members where username = ? and password = ?", [username,encryptPass(password)], one=True)
        if user == None:
            return render_template('login.html', error="Wrong username/password!")
        else:
           session['username'] = username
           return redirect(url_for('main_page'))
    else:
        if len(session) and 'username' in session.keys():
            return redirect(url_for('main_page'))
        else:
            return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    if len(session):
        username = session['username']
        flag = request.args.get('flag')
        try:
            if int(flag)==1:
                session.pop('username', None)
                return redirect(url_for('login'))
            else:
                return redirect(url_for('main_page'))
        except:
            return redirect(url_for('main_page'))
    else:
        return redirect(url_for('login'))

@app.route('/restore')
def restore():
    query = query_db("select username from members where username = ?", ['mpociAdmin'])
    if len(query):
        return "Nothing to restore"
    else:
        db = get_db()
        db.text_factory = str
        password = encryptPass('rahasia')
        db.execute("insert into members (name, username, password, level, time_date_added) values (?, ?, ?, ?, datetime('now', 'localtime'))",
                ['Super Admin', 'mpociadmin', password, 'admin'])
        db.commit()
        db.close()
        return "Restore Success!"

@app.route('/new_member', methods=['POST', 'GET'])
def new_member():
    db = get_db()
    db.text_factory = str
    error = None

    if not checkLogin():
        return redirect(url_for('main_page'))

    if request.method == 'POST':
        fullname = request.form['fullname']
        username = (request.form['username']).lower()
        password = request.form['password']
        access_level = request.form['access-level']

        def checkNewMember(username):
            query = query_db("select username from members where username = ?", [username])
            return len(query)

        if fullname and username and password and access_level:
            password = encryptPass(password)

            if checkNewMember(username):
                return render_template('new_member.html', error="* Username already exist!")

            db.execute("insert into members (name, username, password, level, time_date_added) values (?, ?, ?, ?, datetime('now', 'localtime'))",
                        [fullname, username, password, access_level])
            db.commit()
            return redirect(url_for('main_page'))
        else:
            return render_template('new_member.html', error="* Some fields are empty!")
    else:
        return render_template('new_member.html', error=error)

@app.route('/edit_member', methods=['POST', 'GET'])
def edit_member():
    members = None
    query = query_db('select * from members order by level asc')

    if not checkLogin():
        return redirect(url_for('main_page'))

    if request.method == 'GET':
        try:
            message = None
            edit_flag = request.args.get('edit')
            edit_username = request.args.get('username')
            db = get_db()
            db.text_factory = str
            if edit_flag == '1' and session['username'] != edit_username:
                current_access = query_db('select level from members where username = ?', [edit_username], one=True)
                new_level = 'user' if current_access['level']=='admin' else 'admin'
                db.execute('update members set level = ? where username = ?', [new_level, edit_username])
                db.commit()
                message = "Update Success!"
            elif edit_flag == '0' and session['username'] != edit_username:
                db.execute('delete from members where username = ?', [edit_username])
                db.commit()
                message = "Delete Success!"
            else:
                return render_template('edit_member.html', members=query)
            db.close()
            return redirect(url_for('edit_member'))
        except:
            return render_template('edit_member.html', members=query)
    else:
        return render_template('edit_member.html', members=query)

def projectNameValidation(name):
    result = re.search(r'\w+',name,re.M|re.I)
    return len(result.group()) == len(name)

@app.route('/add_project', methods=['GET','POST'])
def add_project():
    error = None
    if not checkLogin():
        return redirect(url_for('main_page'))

    if request.method == 'POST':
        # check if the post request has the file part
        project_name = request.form['project_name']
        project_name = project_name.lower()
        description = request.form['description']

        if len(request.files.getlist('files[]')) == 1 and ( not project_name or not description ):
            return render_template('add_project.html', error="* Some fields are empty!")
        elif len(request.files.getlist('files[]')) > 1 and ( not project_name or not description ):
            return render_template('add_project.html', error="* Some fields are empty!")
        elif len(request.files.getlist('files[]')) == 1 and ( project_name or description ):
            return render_template('add_project.html', error="* No folder selected!")
        elif len(request.files.getlist('files[]')) > 1 and project_name and description:
            if not projectNameValidation(project_name):
                return render_template('add_project.html', error="* Invalid Project Name!")

            # Check for duplicate project_name
            query = query_db('select project_name from projects where project_name = ?', [project_name])
            if len(query):
                return render_template('add_project.html', error="* Duplicate Project Name!")
            # End of check duplicate lines

            files = request.files.getlist('files[]', None)

            # Insert details of projects in the database
            db = get_db()
            db.text_factory = str
            created_by = session['username']
            db.execute("insert into projects (project_name, description, created_by, created_at, project_status) values (?, ?, ?, datetime('now', 'localtime'), ?)",
                        [project_name, description, created_by, 1])
            db.commit()
            db.close()
            # EOL

            members = query_db("select username from members where username not like ? ", ['mpociadmin'])
            # Start to uploading files
            for f in files:
                fname = f.filename
                fname = fname.split('/')
                fname = [str(i) for i in fname]
                if len(fname) == 1:
                    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER + '/' + project_name + '/' + member.username + '/'
                    f.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(fname[0])))
                else:
                    fTree = [fname[0]] + ["master"] + fname[1:]
                    fTree[0] = project_name
                    directoryTree = UPLOAD_FOLDER
                    for directory in fTree[:len(fTree)-1]:
                        directoryTree += '/' + directory
                        if not os.path.isdir(directoryTree):
                            os.mkdir(directoryTree)
                    app.config['UPLOAD_FOLDER'] = directoryTree
                    f.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(fTree[len(fTree)-1])))
            # EOL

            # Generate Branch Folders Project
            src = UPLOAD_FOLDER + '/' + project_name + '/' + 'master'
            for member in members:
                dst = UPLOAD_FOLDER + '/' + project_name + '/branch-' + member['username']
                shutil.copytree(src,dst)
                shutil.copystat(src,dst)
            # EOL
            return redirect(url_for('main_page'))

    return render_template('add_project.html', error=error)

def dirTree(dir_path):

    DIRECTORY = [dir_path+'/']
    files_list = []

    dir = True

    while dir:
        for i in range(len(DIRECTORY)):
            result = os.listdir(DIRECTORY[i])
            for r in result:
                tmp = DIRECTORY[i] + r + '/'
                if os.path.isdir(tmp):
                    if tmp not in DIRECTORY:
                        DIRECTORY.append(tmp)
                else:
                    tmp = tmp.rstrip('/')
                    if tmp not in files_list:
                        files_list.append(tmp)

            if i == len(DIRECTORY)-1:
                dir = False
    return (DIRECTORY, files_list)

@app.route('/update_project', methods=['GET', 'POST'])
def update_project():
    error = None
    if not len(session) and 'username' not in session.keys():
        return redirect(url_for('main_page'))

    username = session['username']
    project_names = query_db('select project_name from projects',[])

    if request.method == 'POST':
        # check if the post request has the file part
        project_name = request.form['project_name']
        project_name = project_name.lower()
        notes = request.form['notes']

        if len(request.files.getlist('files[]')) == 1 and ( not project_name or not notes ):
            return render_template('update_project.html', error="* Some fields are empty!", project_names=project_names)
        elif len(request.files.getlist('files[]')) > 1 and ( not project_name or not notes ):
            return render_template('update_project.html', error="* Some fields are empty!", project_names=project_names)
        elif len(request.files.getlist('files[]')) == 1 and ( project_name or notes ):
            return render_template('update_project.html', error="* No folders/files selected!", project_names=project_names)
        elif len(request.files.getlist('files[]')) > 1 and project_name and notes:
            if not projectNameValidation(project_name):
                return render_template('update_project.html', error="* Invalid Project Name!", project_names=project_names)

            query = query_db('select * from projects where project_name = ? and project_status = 0', [project_name])
            if query:
                return render_template('update_project.html', error="* Update not allowed, project " + project_name.upper() + " has been disabled!", project_names=project_names)

            src = UPLOAD_FOLDER + '/' + project_name + '/branch-' + username
            dst = '/var/www/qqdewa.test/DATA_BACKUP/' + project_name + '/branch-' + username + '.bak'
            try:
                if os.path.isdir(dst):
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)
                shutil.copystat(src, dst)
            except:
                return "ERROR python 'shutil' module"

            files = request.files.getlist('files[]', None)
            updates_list = []
            files_update_list = []

            if os.path.isdir(src):
                shutil.rmtree(src)

            for f in files:
                fname = f.filename
                fname = fname.split('/')
                fname = [str(i) for i in fname]

                fTree = [fname[0]] + ["branch-" + username] + fname[1:]
                fTree[0] = project_name
                directoryTree = UPLOAD_FOLDER

                # writing new file on server
                for directory in fTree[:len(fTree)-1]:
                    directoryTree += '/' + directory
                    if not os.path.isdir(directoryTree):
                        os.mkdir(directoryTree)
                app.config['UPLOAD_FOLDER'] = directoryTree

                updates_list.append(directoryTree + '/' + fTree[len(fTree)-1])

                f.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(fTree[len(fTree)-1])))
                # EOL

                # compare file between master/branch and data_backup to get the list of updated files
                dst_file = dst + "/" + "/".join(fTree[2:])
                src_file = directoryTree + '/' + fTree[len(fTree)-1]
                new_file = '/' + project_name + '/' + '/'.join(fTree[1:])
                if os.path.exists(dst_file):
                    if not filecmp.cmp(src_file, dst_file):
                        files_update_list.append(new_file)
                else:
                    files_update_list.append(new_file)
                files_update_list.sort()
                # EOL

            # Check files or folder that are deleted in the new updates
            files_removed = []
            _, old_files = dirTree(dst)
            for f in old_files:
                f = re.sub('DATA_BACKUP', 'html', f)
                f = re.sub('.bak', '', f)
                if f not in updates_list:
                    files_removed.append(f)
            # EOL

            files_update = ';'.join(files_update_list) + '-' + ';'.join(files_removed)
            # Update 'activity' table
            if files_update_list:
                db = get_db()
                db.text_factory = str
                db.execute("update activity set revert_status = 1 where project_name = ? and updated_by = ?", [project_name, username])
                db.commit()
                query = query_db('select * from activity where project_name = ? and updated_by = ?', [project_name, username])
                for q in query:
                    activity_id = q['id']
                    #db.execute("insert into revert_activity (activity_id, project_name, branch_name, reverted_by, reverted_at) values (?, ?, ?, ?, datetime('now','localtime'))",
                    #            [activity_id, project_name, "branch-"+username, username])
                    #db.commit()
                db.execute("insert into activity (project_name, branch_name, files_list, updated_by, updated_at, notes, admin_response, merge_status, merge_notes, revert_status, review_status, activity_status, activity_notes) values (?, ?, ?, ?, datetime('now','localtime'), ?, ?, ?, ?, ?, ?, ?, ?)",
                            [project_name, "branch-"+username, files_update, username, notes, '-', 0, '-', 0, 0, 1, '-'])
                db.commit()
                db.close()
            # EOL

        return redirect(url_for('main_page'))

    return render_template('update_project.html', error=error, project_names=project_names)

@app.route('/project_details', methods=['GET','POST'])
def project_details(name=None):
    if not len(session) and 'username' not in session.keys():
        return redirect(url_for('main_page'))
    error = None
    project_name = None
    details = None
    activities = None
    username = session['username']
    userlevel = 1 if checkLogin() else None

    if request.method == 'GET':
        if name:
            project_name = name
        else:
            project_name = request.args.get('name')
        if not project_name:
            return redirect(url_for('main_page'))

        details = query_db('select * from projects where project_name = ?', [project_name.lower()], one=True)
        if not details:
            return redirect(url_for('main_page'))

        dirs, files = dirTree(UPLOAD_FOLDER + '/' + project_name + '/master')
        for i in range(len(dirs)):
            dirs[i] = re.sub(UPLOAD_FOLDER,'',dirs[i])
        for i in range(len(files)):
            files[i] = re.sub(UPLOAD_FOLDER,'',files[i])
        activities = query_db('select * from activity where project_name = ? order by updated_at DESC', [project_name.lower()])
        return render_template('project_details.html', details=details, files=dirs+files, activities=activities, userlevel=userlevel)
    else:
        return redirect(url_for('main_page'))

@app.route('/view_project', methods=['GET','POST'])
def view_project():
    if not len(session) and 'username' not in session.keys():
        return redirect(url_for('main_page'))
    error = None
    project_name = None
    username = session['username']

    # Check if View link is selected, if Yes it will update the table
    view = request.args.get('view')
    project_name = request.args.get('project_name')
    activity_id = request.args.get('activity_id')
    if view and project_name and activity_id and checkLogin():
        try:
            activity_id = int(activity_id)
        except:
            return redirect(url_for('main_page'))
        db = get_db()
        db.text_factory = str
        db.execute('update activity set review_status=1 where id=?',[activity_id])
        db.commit()
        db.close()
        return redirect("http://qqdewa.test/" + project_name + '/' + "branch-" + username)
    return redirect(url_for('main_page'))
    # EOL

@app.route('/delete_project', methods=['GET','POST'])
def delete_project():
    error = None
    if not checkLogin():
        return redirect(url_for('main_page'))
    flag = request.args.get('flag')
    project_name = request.args.get('project_name')

    if flag and project_name:
        db = get_db()
        db.text_factory = str
        try:
            if flag=='0':
                db.execute('update projects set project_status = 0 where project_name = ?', [project_name])
                db.commit()
            elif flag=='1':
                db.execute('update projects set project_status = 1 where project_name = ?', [project_name])
                db.commit()
            elif flag=='2':
                db.execute('delete from projects where project_name = ?', [project_name])
                db.commit()
                db.execute('delete from activity where project_name = ?', [project_name])
                db.commit()
                src = UPLOAD_FOLDER + '/' + project_name
                dst = '/var/www/qqdewa.test/DATA_BACKUP/' + project_name
                try:
                    if os.path.isdir(dst):
                        shutil.rmtree(dst)
                    if os.path.isdir(src):
                        shutil.rmtree(src)
                except:
                    return redirect(url_for('main_page'))
                return redirect(url_for('main_page'))
            return redirect('http://mpoci.portal/project_details?name=' + project_name)
        except:
            return redirect(url_for('main_page'))
        db.close()

    return redirect(url_for('main_page'))

@app.route('/activity_details', methods=['GET','POST'])
def activity_details():
    if not len(session) and 'username' not in session.keys():
        return redirect(url_for('main_page'))
    error = None
    details = None
    project_status = None
    activity_id = None
    #reverted_activity = None
    username = session['username']
    userlevel = 1 if checkLogin() else None
    if request.method == 'GET':
        activity_id = request.args.get('act_id')
        try:
            activity_id = int(activity_id)
        except:
            return redirect(url_for('main_page'))

        details = query_db('select * from activity where id = ?', [activity_id], one=True)
        if not details:
            return redirect(url_for('main_page'))

        dirs, files = dirTree(UPLOAD_FOLDER + '/' + details['project_name'] + '/branch-' + details['updated_by'])
        for i in range(len(dirs)):
            dirs[i] = re.sub(UPLOAD_FOLDER,'',dirs[i])
        for i in range(len(files)):
            files[i] = re.sub(UPLOAD_FOLDER,'',files[i])
        project_status = query_db('select project_status from projects where project_name = ?', [details['project_name']], one=True)
        #reverted_activity = query_db('select * from revert_activity where activity_id = ?', [activity_id], one=True)
        return render_template('activity_details.html', details=details, project_status=project_status, files=dirs+files, userlevel=userlevel)
    else:
        return redirect(url_for('main_page'))

@app.route('/merge', methods=['GET','POST'])
def merge():
    if not checkLogin():
        return redirect(url_for('main_page'))
    flag = None
    if request.method == 'POST':
        notes = request.form['merge-notes']
        return notes
    else:
        return redirect(url_for('main_page'))
    return redirect(url_for('main_page'))

@app.route('/close_activity', methods=['GET','POST'])
def close_activity():
    if not checkLogin():
        return redirect(url_for('main_page'))
    flag = None
    if request.method == 'POST':
        notes = request.form['close-notes']
        return notes
    else:
        return redirect(url_for('main_page'))
    return redirect(url_for('main_page'))

@app.route('/revert_updates', methods=['GET','POST'])
def revert_updates():
    if not len(session) and 'username' not in session.keys():
        return redirect(url_for('main_page'))
    flag = None
    activity_id = None
    username = session['username']
    userlevel = 1 if checkLogin() else None
    if request.method == 'GET':
        flag = request.args.get('flag')
        activity_id = request.args.get('act_id')

        if flag != '1':
            return redirect(url_for('main_page'))

        try:
            activity_id = int(activity_id)
        except:
            return redirect(url_for('main_page'))

        revert_query = query_db('select * from activity where id = ?', [activity_id], one=True)

        db = get_db()
        db.text_factory = str

        if revert_query:
            if revert_query['updated_by'] != username or not checkLogin():
                return redirect(url_for('main_page'))
            project_name = revert_query['project_name']
            branch_name = revert_query['branch_name']
            db.execute("update activity set revert_status = 1 where id = ?", [activity_id])
            db.commit()
            db.execute("insert into revert_activity (activity_id, project_name, branch_name, reverted_by, reverted_at) values (?, ?, ?, ?, datetime('now','localtime'))",
                        [activity_id, project_name, branch_name, username])
            db.commit()
            old_dir_path = '/var/www/qqdewa.test/DATA_BACKUP/' + project_name + '/' + branch_name + '.bak'
            current_dir_path = UPLOAD_FOLDER + '/' + project_name + '/' + branch_name
            try:
                if os.path.isdir(current_dir_path):
                    shutil.rmtree(current_dir_path)
                shutil.copytree(old_dir_path, current_dir_path)
                shutil.copystat(old_dir_path, current_dir_path)
            except:
                return "ERROR SHUTIL MODULE"
            db.close()
            return redirect('http://mpoci.portal/activity_details?act_id=' + str(activity_id))
        else:
            return redirect(url_for('main_page'))
    else:
        return redirect(url_for('main_page'))

if __name__ == '__main__':
    app.run(host='0.0.0.0')
