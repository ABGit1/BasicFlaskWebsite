from flask import Flask, request, jsonify, redirect, render_template, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user 
import sqlite3
import bcrypt
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'example_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database connection 
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# User loader for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user_row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user_row:
        user = User(user_row['id'], user_row['username'], user_row['role'])
        return user
    return None

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']  #member or manager

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        encryption_key = Fernet.generate_key().decode() #encryption key for the user
        # Store the encryption key

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password, role, encryption_key) VALUES (?, ?, ?, ?)',
                         (username, hashed_password, role, encryption_key))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists!"
        finally:
            conn.close()

        return redirect(url_for('login'))

    return render_template('register.html')

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone() #sql to get row
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']): #logging in with the user deatils
            user_obj = User(id=user['id'], username=user['username'], role=user['role'])
            login_user(user_obj) #login library to login the user
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials"

    return render_template('login.html') #html page for login

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    #different dashboards for different roles (different html)
    if current_user.role == 'manager':
        return render_template('manager_dashboard.html') #render from templates folder
    else:
        return render_template('member_dashboard.html')

# Create task route
@app.route('/create_task', methods=['GET', 'POST'])
@login_required #check if the user is logged in
def create_task():
    if current_user.role != 'manager': # Only managers can create tasks
        return "Unauthorized", 403 #return ends function and returns the error

    if request.method == 'POST': #check if the request is a post request
        title = request.form['title']
        description = request.form['description']
        assigned_to = request.form['assigned_to']  # user id

        conn = get_db_connection()
        conn.execute('INSERT INTO tasks (title, description, assigned_to, status) VALUES (?, ?, ?, ?)',
                     (title, description, assigned_to, 'Pending')) #default status is pending making a new row here 
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users WHERE role="member"').fetchall() # Get all members to assign tasks
    conn.close()
    return render_template('create_task.html', users=users) #html page for creating tasks

# Task list display
@app.route('/task_list')
@login_required
def task_list():
    conn = get_db_connection()
    tasks = None
    if current_user.role == 'manager':
        # * means all in sql!
        #use sql to get all the tasks and join with the users table to get the username of the assigned user
        #manager can see all tasks
        tasks = conn.execute('SELECT tasks.*, users.username AS assigned_to_name FROM tasks LEFT JOIN users ON tasks.assigned_to = users.id').fetchall()
    else:
        # Members can only see their own tasks
        tasks = conn.execute('SELECT tasks.*, users.username AS assigned_to_name FROM tasks LEFT JOIN users ON tasks.assigned_to = users.id WHERE assigned_to = ?', (current_user.id,)).fetchall()
    conn.close()
    #display the tasks in a table format
    return render_template('task_list.html', tasks=tasks)

@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
#edit task route
def edit_task(task_id):
    conn = get_db_connection()
    task = conn.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()

    # Check if task exists
    if not task:
        conn.close()
        return "Task not found", 404

    # Members can only edit their own tasks
    if current_user.role == 'member' and task['assigned_to'] != current_user.id:
        conn.close()
        return "Unauthorized", 403

    if request.method == 'POST':
        #we fill out a form to edit the task and submit it
        new_status = request.form['status']
        #change the status of the task in the database
        conn.execute('UPDATE tasks SET status = ? WHERE id = ?', (new_status, task_id))
        conn.commit()
        conn.close()
        return redirect(url_for('task_list'))

    conn.close()
    return render_template('edit_task.html', task=task)

@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    conn = get_db_connection()
    task = conn.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()

    if not task:
        conn.close()
        return "Task not found", 404

    # Only allow managers to delete tasks
    if current_user.role != 'manager':
        conn.close()
        return "Unauthorized", 403

    conn.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('task_list'))

# Logout route
@app.route('/logout')
@login_required
#loging out the user with the library we imported
def logout():
    logout_user()
    return redirect(url_for('login'))

# Run the app
if __name__ == "__main__":
    app.run(debug=True)
