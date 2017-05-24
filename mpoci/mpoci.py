import os
import shutil
import filecmp
import re
from datetime import datetime
import sqlite3
import time
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

#http_server = WSGIServer(('', 5000), app)

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

def projectNameValidation(name):
    result = re.search(r'\w+',name,re.M|re.I)
    return len(result.group()) == len(name)

def sortProjects(projects):
    P = [i for i in projects]
    i = 0
    n = 2 if len(P) > 2 else 1
    while i < len(P)-n:
        x = P[i]['project_name']
        y = P[i+1]['project_name']
        if x > y:
            P[i],P[i+1] = P[i+1],P[i]
        if i != 0:
            i -= 1
        else:
            i += 1
    return P

def sortActivity(activity):
    A = [i for i in activity]
    i = 0
    n = 2 if len(A) > 2 else 1
    while i < len(A)-n:
        Ax = A[i]['updated_at'].split(' ')
        Ay = A[i+1]['updated_at'].split(' ')
        Ax = Ax[0].split('-')+Ax[1].split(':')
        Ay = Ay[0].split('-')+Ay[1].split(':')
        Ax = [int(j) for j in Ax]
        Ay = [int(j) for j in Ay]
        Ax = datetime(Ax[0],Ax[1],Ax[2],Ax[3],Ax[4],Ax[5])
        Ay = datetime(Ay[0],Ay[1],Ay[2],Ay[3],Ay[4],Ay[5])

        if Ax < Ay:
            A[i],A[i+1] = A[i+1], A[i]
        if i != 0:
            i -= 1
        else:
            i += 1
    return A

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

@app.route('/', methods=['GET','POST'])
def main_page():
    error = None
    username = None
    projects = None
    admin = 1 if checkLogin() else None
    fileList = None
    projectName = None
    activities = None
    deactivatedMember = None

    if request.method == 'GET':
        if len(session):
            if 'username' in session.keys():
                username = session['username']
                projects = query_db('select * from projects order by project_name',[])
                members = query_db('select * from members where username != ? and member_status = ? order by username',['rootadmin',1])
                fileList = []

                if 'project_name' in session.keys():
                    project_name = session['project_name']
                    projectName = project_name
                elif projects:
                    projectName = projects[0]['project_name']
                else:
                    return render_template('main_page.html', error=error, username=username, admin=admin, projects=projects, fileList=fileList, projectName=projectName, activities=activities)

                dirs, files = dirTree(UPLOAD_FOLDER + '/' + projectName + '/master')
                for i in range(len(files)):
                    files[i] = re.sub(UPLOAD_FOLDER,'',files[i])
                fileList.append(['master',files])
                for m in members:
                    branch = "branch-" + m['username']
                    dirs, files = dirTree(UPLOAD_FOLDER + '/' + projectName + '/' + branch)
                    for i in range(len(files)):
                        files[i] = re.sub(UPLOAD_FOLDER,'',files[i])
                    fileList.append([branch,files])
                activities = query_db('select * from activity where project_name = ? and revert_status = 0 and merge_status != 2  and close_status = 0 order by updated_at desc limit 10', [projectName])

                #return str(fileList)+str(len(fileList))
                return render_template('main_page.html', error=error, username=username, admin=admin, projects=projects, fileList=fileList, projectName=projectName, activities=activities)
            else:
                return redirect(url_for('login'))
        else:
            return redirect(url_for('login'))
    else:
        if len(session):
            if 'username' in session.keys():
                username = session['username']
                project_name = request.form['dropdown_project']
                session['project_name'] = project_name
                projects = query_db('select * from projects order by project_name',[])
                members = query_db('select * from members where username != ? order by level',['rootadmin'])
                fileList = []
                dirs, files = dirTree(UPLOAD_FOLDER + '/' + project_name + '/master')
                for i in range(len(files)):
                    files[i] = re.sub(UPLOAD_FOLDER,'',files[i])
                fileList.append(['master',files])
                for m in members:
                    branch = "branch-" + m['username']
                    dirs, files = dirTree(UPLOAD_FOLDER + '/' + project_name + '/' + branch)
                    for i in range(len(files)):
                        files[i] = re.sub(UPLOAD_FOLDER,'',files[i])
                    fileList.append([branch,files])
                activities = query_db('select * from activity where project_name = ? and revert_status = 0 and merge_status != 2 and close_status = 0 order by updated_at desc limit 10', [project_name])
                return render_template('main_page.html', error=error, username=username, admin=admin, projects=projects, fileList=fileList, projectName=project_name, activities=activities)
    return render_template('main_page.html', error=error)

@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None

    if request.method == 'POST':
        username = (request.form['username']).lower()
        password = request.form['password']
        user = query_db("select username,password,level,member_status from members where username = ? and password = ?", [username,encryptPass(password)], one=True)
        if user == None:
            return render_template('login.html', error="Wrong username/password!")
        elif user['member_status'] == 1:
           session['username'] = username
           return redirect(url_for('main_page'))
        else:
           return render_template('login.html', error="Username has been deleted!")
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
                session.pop('project_name', None)
                return redirect(url_for('login'))
            else:
                return redirect(url_for('main_page'))
        except:
            return redirect(url_for('main_page'))
    else:
        return redirect(url_for('login'))

# Create user 'rootadmin' to restore portal access
@app.route('/restore')
def restore():
    query = query_db("select username from members where username = ?", ['rootadmin'])
    if len(query):
        return "Nothing to restore"
    else:
        db = get_db()
        db.text_factory = str
        password = encryptPass('password')
        db.execute("insert into members (name, username, password, level, time_date_added, member_status) values (?, ?, ?, ?, datetime('now', 'localtime'), ?)",
                ['Super Admin', 'rootadmin', password, 'admin', 1])
        db.commit()
        db.close()
        return "Restore Success!"
# EOL

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

            db.execute("insert into members (name, username, password, level, time_date_added, member_status) values (?, ?, ?, ?, datetime('now', 'localtime'), ?)",
                        [fullname, username, password, access_level, 1])
            db.commit()

            projects = query_db('select * from projects',[])
            if projects:
                try:
                    for project in projects:
                        project_name = project['project_name']
                        src = UPLOAD_FOLDER + '/' + project_name + '/master'
                        dst = UPLOAD_FOLDER + '/' + project_name + '/branch-' + username
                        shutil.copytree(src,dst)
                        shutil.copystat(src,dst)
                except:
                    return "ERROR SHUTIL MODULE"

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
            elif edit_flag == '2' and session['username'] != edit_username:
                db.execute('update members set member_status = ? where username = ?', [0, edit_username])
                db.commit()
                projects = query_db('select * from projects',[])
                if projects:
                    try:
                        for project in projects:
                            project_name = project['project_name']
                            dst = UPLOAD_FOLDER + '/' + project_name + '/branch-' + edit_username
                            if os.path.isdir(dst):
                                shutil.rmtree(dst)
                    except:
                        return "ERROR SHUTIL MODULE"
            elif edit_flag == '3' and session['username'] != edit_username:
                db.execute('update members set member_status = ? where username = ?', [1, edit_username])
                db.commit()
                projects = query_db('select * from projects',[])
                if projects:
                    try:
                        for project in projects:
                            project_name = project['project_name']
                            src = UPLOAD_FOLDER + '/' + project_name + '/master'
                            dst = UPLOAD_FOLDER + '/' + project_name + '/branch-' + edit_username
                            shutil.copytree(src,dst)
                            shutil.copystat(src,dst)
                    except:
                        return "ERROR SHUTIL MODULE"
            else:
                return render_template('edit_member.html', members=query)
            db.close()
            return redirect(url_for('edit_member'))
        except:
            return render_template('edit_member.html', members=query)
    else:
        return render_template('edit_member.html', members=query)

@app.route('/add_project', methods=['GET','POST'])
def add_project():
    error = None
    if not len(session) and 'username' not in session.keys():
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

            members = query_db("select username from members where username not like ? ", ['rootadmin'])
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
            if files_update_list or files_removed:
                db = get_db()
                db.text_factory = str
                db.execute("update activity set revert_status = 1 where project_name = ? and updated_by = ?", [project_name, username])
                db.commit()
                db.execute("insert into activity (project_name, branch_name, files_list, updated_by, updated_at, notes, revert_status, review_status, merge_status, merge_by, merge_at, merge_notes, close_status, close_by, close_at, close_notes) values (?, ?, ?, ?, datetime('now','localtime'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            [project_name, "branch-"+username, files_update, username, notes, 0, 0, 0, '-', '-', '-', 0, '-', '-', '-'])
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
    activities = []
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

        activities = query_db('select * from activity where project_name = ? order by updated_at desc limit 20', [project_name])
        #query = query_db('select * from members where username != ?',['rootadmin'])
        #for q in query:
        #    name_activity = query_db('select * from activity where project_name = ? and updated_by = ? order by updated_at', [project_name, q['username']], one=True)
        #    if name_activity:
        #        activities.append(name_activity)
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
    if view and project_name and activity_id:
        try:
            activity_id = int(activity_id)
        except:
            return redirect(url_for('main_page'))
        if checkLogin():
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
                session.pop('project_name', None)
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
        username = session['username']
        notes = request.form['merge-notes']
        activity_id = request.form['act_id']
        try:
            activity_id = int(activity_id)
        except:
            return redirect(url_for('main_page'))
        if not activity_id:
            return redirect(url_for('main_page'))
        query = query_db('select project_name, updated_by from activity where id = ?',[activity_id], one=True)
        if not query:
            return redirect(url_for('main_page'))
        project_name = query['project_name']
        branch_name = 'branch-' + query['updated_by']
        master_path = UPLOAD_FOLDER + '/' + project_name + '/master'
        branch_path = UPLOAD_FOLDER + '/' + project_name + '/' + branch_name
        try:
            if os.path.isdir(master_path):
                shutil.rmtree(master_path)
            shutil.copytree(branch_path, master_path)
            shutil.copystat(branch_path, master_path)
        except:
            return "ERROR SHUTIL MODULE"
        db = get_db()
        db.text_factory = str
        db.execute("update activity set review_status = ?, merge_status=?, merge_by = ?, merge_at = datetime('now','localtime'), merge_notes = ? where id = ?", [1, 1, username, notes, activity_id])
        db.commit()
        db.close()
        return redirect("http://mpoci.portal/activity_details?act_id=" + str(activity_id))

    return redirect(url_for('main_page'))

@app.route('/close_ticket', methods=['GET','POST'])
def close_ticket():
    if not checkLogin():
        return redirect(url_for('main_page'))
    flag = None
    if request.method == 'POST':
        username = session['username']
        notes = request.form['close-notes']
        activity_id = request.form['act_id']
        try:
            activity_id = int(activity_id)
        except:
            return redirect(url_for('main_page'))
        if not activity_id:
            return redirect(url_for('main_page'))
        db = get_db()
        db.text_factory = str
        db.execute("update activity set review_status = ?, close_status=?, close_by = ?, close_at = datetime('now','localtime'), close_notes = ? where id = ?", [1, 1, username, notes, activity_id])
        db.commit()
        db.close()
        return redirect("http://mpoci.portal/activity_details?act_id=" + str(activity_id))

    return redirect(url_for('main_page'))

@app.route('/merge_history', methods=['GET','POST'])
def merge_history():
    if not len(session) and 'username' not in session.keys():
        return redirect(url_for('main_page'))
    error = None
    mergeHistory = None
    if request.method == 'GET':
        mergeHistory = query_db('select * from activity where merge_status = 1 order by updated_at',[])
        return render_template('merge_history.html', mergeHistory=mergeHistory)
    return render_template('merge_history.html')

"""
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
"""

if __name__ == '__main__':
    app.run(threaded=True)
