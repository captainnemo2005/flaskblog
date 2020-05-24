from flaskblog import bcrypt
from flaskblog.users.forms import RegistrationForm,LoginForm,UpdateAccountForm,ResetPasswordForm,ResetRequestForm
from flask_login import current_user,login_required,logout_user,login_user
from flask import flash, url_for, redirect,request,Blueprint,render_template
from flaskblog import db
from flaskblog.models import User,Post
from flaskblog.users.utils import save_picture,send_reset_email
from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField,PasswordField
from wtforms.validators import DataRequired,Email,ValidationError,EqualTo

users = Blueprint('users',__name__)


@users.route("/register",methods=['POST','GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hash_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data,email=form.email.data,password=hash_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in','success')
        return redirect(url_for('users.login'))
    return render_template('register.html',title='Register',form=form)

@users.route("/login",methods=['POST','GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password,form.password.data):
            login_user(user,remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.home'))
        else:
            flash('Login Unsuccessfully. Please check the email  and password','danger')
    return render_template('login.html',title='login',form=form)

@users.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@users.route("/account",methods=['POST','GET'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated','success')
        return redirect(url_for('users.account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static',filename='profile_pics/'+current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file,form=form)

@users.route("/user/<string:username>")
def user_posts(username):
    page = request.args.get('get',1,type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user)\
            .order_by(Post.date_posted.desc())\
            .paginate(page=page,per_page=3)
    return render_template('user_posts.html',posts=posts,user=user)

@users.route("/reset_password",methods=['POST','GET'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = ResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been send with instructions to reset your password.','info')
        return redirect(url_for('users.login'))
    return render_template('reset_request.html', title="Reset Password", form=form)

@users.route("/reset_password/<token>",methods=['POST','GET'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token','warning')
        return redirect(url_for('users.reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hash_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hash_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('main.login'))
    return render_template('reset_token.html', title="Reset Password", form=form)


class ResetRequestForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request password reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user == None:
                raise ValidationError('The email you enter not exist. You have to been sign up first')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset password')