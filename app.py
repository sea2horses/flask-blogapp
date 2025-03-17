from flask import Flask, render_template, session, request, redirect, url_for
from flask_wtf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash, gen_salt
from datetime import datetime

app = Flask(import_name=__name__)
# configure the SQLite database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
# initialize the app with the extension
db = SQLAlchemy(app=app)
# CSRF Token
csrf = CSRFProtect(app)

# Set the secret key to some random bytes. Keep this really secret!
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# Make models
class User(db.Model):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(32), unique=True, nullable=False)
    password = Column(String(128))

    salt_size = 64
    salt = Column(String(salt_size))

    def set_password(self, password):
        self.salt = gen_salt(64)
        self.password = generate_password_hash(self.salt + password)
    
    def check_password(self, password):
        return check_password_hash(self.password, self.salt + password)

class Post(db.Model):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True)
    post_author = Column(Integer, ForeignKey('users.id'))
    # Post Information
    title = Column(String(32))
    content = Column(Text, nullable = True)
    time_created = Column(DateTime, default=datetime.now)

    def get_author(self):
        u = User.query.filter(self.post_author == User.id).first()
        return u
    
    def get_author_username(self):
        u: User = self.get_author()
        if not u:
            return "[deleted]"
        else:
            return u.username

# Home Page    
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    posts = Post.query.all()
    posts.reverse()

    return render_template('index.html', posts=posts)

# Account Page
# @app.route('/me')
# def me():
#     if 'username' in session:
#         return 'about.html'
#     else:
#         return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        u: User = User.query.filter_by(username=username).first()

        if not u:
            return render_template('login.html', message="User doesn't exist")
        elif(u.check_password(password)):
            session['username'] = username
            session['user_id'] = u.id
            return redirect(url_for('index'))
        else:
            return render_template('login.html', message="Incorrect password")
    return render_template('login.html')

@app.route(rule='/logout')
def logout():
    # Remove username from session
    session.pop('username', None)
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route(rule='/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirmpassword = request.form['confirm-password']

        # If passwords don't match
        if password != confirmpassword:
            return render_template('signup.html', message="Passwords don't match")

        # Else, try to make the user
        u = User(username=username)
        u.set_password(password)

        try:
            db.session.add(u)
            db.session.commit()
        except:
            return render_template('signup.html', message="There was an issue making the user")
        # Else, all good!
        session['username'] = username
        session['user_id'] = u.id
        return redirect(url_for('index'))

    else:
        return render_template('signup.html')

@app.route(rule='/writepost', methods=['GET', 'POST'])
def writepost():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        p = Post(title=title, content=content, post_author=session['user_id'])
        try:
            db.session.add(p)
            db.session.commit()

            return redirect(url_for('index'))
        except Exception as e:
            return render_template('writepost.html', message='Something went wrong')

    return render_template('writepost.html')

@app.route(rule='/delete/<int:post_id>', methods=['GET', 'POST'])
def delete(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    p: Post = Post.query.filter(Post.id == post_id).first()

    if not p:
        return render_template('error.html', message="Post doesn't exist")  
    if p.post_author != session['user_id']:
        return render_template('error.html', message="Access Denied")
    
    if request.method == 'POST':
        try:
            db.session.delete(p)
            db.session.commit()

            return redirect(url_for('index'))
        except Exception as e:
            return render_template('delete.html', post=p, message=f"Something went wrong")

    return render_template('delete.html', post=p)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)