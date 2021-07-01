from flask import Flask, render_template, flash, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database1.db'
app.config['SECRET_KEY'] = 'thisissecretkey'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


loginmanager = LoginManager()
loginmanager.init_app(app)
loginmanager.login_view = 'login'

@loginmanager.user_loader
def load_user(userid):
    return User.query.get(int(userid))

# database has to be created after the class is created.

if not path.exists('database1.db'):
    db.create_all(app=app)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={
        'placeholder': 'username'
    })
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=20)], render_kw={
        'placeholder': 'password'
    })
    submit = SubmitField("Register")

    # TO validate the username to be unique
    def validate_username(self, username):
        flash('doing validating user ....')
        # must use username = username.data. without .data i won't raise the ValidationError
        existed_user = User.query.filter_by(username=username.data).first()
        if existed_user:
            raise ValidationError('This username has been registered, choose another username or go to login page')


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={
        'placeholder': 'username'
    })
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=20)], render_kw={
        'placeholder': 'password'
    })
    submit = SubmitField("Login")


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
     #     query if the user is existed
        user = User.query.filter_by(username = form.username.data).first()
        if user:
    #         check if the password match
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    # registered_user = User.query.filter_by(username = form.username.data)
    if form.validate_on_submit():
        #  what if the username has been registered? go to RegistrationForm to fire the validate_username method
        newusername = form.username.data
        newpassword = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=newusername, password=newpassword)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user = current_user)


if __name__ == "__main__":
    app.run(debug=True)
