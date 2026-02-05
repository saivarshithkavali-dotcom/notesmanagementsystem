from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secret_key"   # change in production
DATABASE = "notes.db"


# ---------------- Database Helper ----------------
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------- Home ----------------
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('viewall'))
    return redirect(url_for('login'))


# ---------------- Register ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for('register'))

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email)
        )
        if cur.fetchone():
            conn.close()
            flash("Username or Email already exists.", "danger")
            return redirect(url_for('register'))

        cur.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, generate_password_hash(password))
        )
        conn.commit()
        conn.close()

        flash("Registration successful. Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


# ---------------- Login ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash("Login successful.", "success")
            return redirect(url_for('viewall'))

        flash("Invalid username or password.", "danger")

    return render_template('login.html')


# ---------------- Logout ----------------
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))


# ---------------- Add Note ----------------
@app.route('/addnote', methods=['GET', 'POST'])
def addnote():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()

        if not title or not content:
            flash("Title and content cannot be empty.", "danger")
            return redirect(url_for('addnote'))

        conn = get_db_connection()
        conn.execute(
            "INSERT INTO notes (title, content, user_id) VALUES (?, ?, ?)",
            (title, content, session['user_id'])
        )
        conn.commit()
        conn.close()

        flash("Note added successfully.", "success")
        return redirect(url_for('viewall'))

    return render_template('addnote.html')


# ---------------- View All Notes ----------------
@app.route('/viewall')
def viewall():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    notes = conn.execute(
        "SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC",
        (session['user_id'],)
    ).fetchall()
    conn.close()

    return render_template('viewall.html', notes=notes)


# ---------------- View Single Note ----------------
@app.route('/viewnotes/<int:note_id>')
def viewnotes(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    note = conn.execute(
        "SELECT * FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session['user_id'])
    ).fetchone()
    conn.close()

    if not note:
        flash("Note not found or unauthorized.", "danger")
        return redirect(url_for('viewall'))

    return render_template('singlenote.html', note=note)


# ---------------- Update Note ----------------
@app.route('/updatenote/<int:note_id>', methods=['GET', 'POST'])
def updatenote(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    note = conn.execute(
        "SELECT * FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session['user_id'])
    ).fetchone()

    if not note:
        conn.close()
        flash("Unauthorized access.", "danger")
        return redirect(url_for('viewall'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        conn.execute(
            "UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?",
            (title, content, note_id, session['user_id'])
        )
        conn.commit()
        conn.close()

        flash("Note updated successfully.", "success")
        return redirect(url_for('viewall'))

    conn.close()
    return render_template('updatenote.html', note=note)


# ---------------- Delete Note ----------------
@app.route('/deletenote/<int:note_id>', methods=['POST'])
def deletenote(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute(
        "DELETE FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session['user_id'])
    )
    conn.commit()
    conn.close()

    flash("Note deleted.", "info")
    return redirect(url_for('viewall'))


# ---------------- Forgot Password ----------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip()

        conn = get_db_connection()
        user = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()
        conn.close()

        if user:
            session['reset_user_id'] = user['id']
            return redirect(url_for('reset_password'))

        flash("Email not found.", "danger")

    return render_template('forgot_password.html')


# ---------------- Reset Password ----------------
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']

        if not password:
            flash("Password cannot be empty.", "danger")
            return redirect(url_for('reset_password'))

        conn = get_db_connection()
        conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (generate_password_hash(password), session['reset_user_id'])
        )
        conn.commit()
        conn.close()

        session.pop('reset_user_id')
        flash("Password reset successful.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')


# ---------------- Run App ----------------
if __name__ == '__main__':
    app.run(debug=True)