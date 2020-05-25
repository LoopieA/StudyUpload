import os
import sys
from os import listdir
from os.path import isfile, join
from flask import Flask, render_template, request, flash, redirect, url_for, send_file, send_from_directory
from flask_wtf import FlaskForm, RecaptchaField
from flask_bootstrap import Bootstrap
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_humanize import Humanize
from flask import abort

app = Flask(__name__)
Bootstrap(app)
humanize = Humanize(app)

app.secret_key = "112"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(ROOT_DIR, "static/files")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=80)])
    remember = BooleanField('Remember me')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=80)])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def main():
    return render_template('index.html')

@app.route('/upload')
@login_required
def index():
    return render_template("upload.html")

@app.route('/fise')
def fise():
    filesizes = []
    class_query = request.args.get('class')
    try:
        onlyfiles = [f for f in listdir(UPLOAD_FOLDER + "/" + class_query) if isfile(join(UPLOAD_FOLDER + "/" + class_query, f))]
    except:
        abort(404)
    for size in onlyfiles:
        filesizes.append(os.path.getsize(UPLOAD_FOLDER + '/' + class_query + '/' + size))
    totalfilesize = sum(filesizes)
    files = zip(onlyfiles, filesizes)
    print(filesizes, file=sys.stdout)
    return render_template("fise.html", onlyfiles=files, totalfilesize=totalfilesize, files=onlyfiles, query=class_query)

@app.route('/uploads/<path:filename>', methods=['GET', 'POST'])
def return_file():
    class_query = request.args.get('class')
    onlyfiles = [f for f in listdir(UPLOAD_FOLDER + "/" + class_query) if isfile(join(UPLOAD_FOLDER + "/" + class_query, f))]
    uploads = os.path.join(ROOT_DIR, app.config['UPLOAD_FOLDER'] + "/" + class_query)

    for file in onlyfiles:
        return send_from_directory(directory=uploads, filename=file)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('main'))
            else:
                flash('Invalid password', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('main'))
    return render_template("register.html", form=form)

@app.route('/uploader', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', 'upload')
            return redirect(request.url)
        file = request.files['file']
        class_select_result = request.form.get("class_select")
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'] + "/" + class_select_result.lower(), filename))
            flash("Upload successful!", 'upload')
            return render_template("index.html")
        elif not allowed_file(file.filename):
            flash(file.filename.rsplit('.', 1)[1].lower() + " extension is not allowed.")
            return render_template("index.html")
    else:
        flash("Upload failed", 'upload')
        return render_template("index.html")


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)