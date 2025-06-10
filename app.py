from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Модель пользователя
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


# Форма редактирования профиля
class EditProfileForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    current_password = PasswordField('Текущий пароль', validators=[DataRequired()])
    new_password = PasswordField('Новый пароль (оставьте пустым, если не хотите менять)',
                                 validators=[Optional(), Length(min=8, max=100)])
    confirm_password = PasswordField('Подтвердите новый пароль',
                                     validators=[EqualTo('new_password', message='Пароли должны совпадать')])
    submit = SubmitField('Сохранить изменения')


# Форма входа
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Исправлено здесь


@app.route('/')
def home():
    return render_template('base.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('edit_profile'))
        flash('Неверный email или пароль', 'danger')
    return render_template('login.html', form=form)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(obj=current_user)

    if form.validate_on_submit():
        # Проверка текущего пароля
        if not check_password_hash(current_user.password, form.current_password.data):
            flash('Неверный текущий пароль', 'danger')
            return render_template('edit_profile.html', form=form)

        # Проверка уникальности email
        if form.email.data != current_user.email and User.query.filter_by(email=form.email.data).first():
            flash('Этот email уже используется другим пользователем', 'danger')
            return render_template('edit_profile.html', form=form)

        # Обновление данных пользователя
        current_user.username = form.username.data
        current_user.email = form.email.data

        # Обновление пароля, если указан новый
        if form.new_password.data:
            current_user.password = generate_password_hash(form.new_password.data)

        db.session.commit()
        flash('Профиль успешно обновлен!', 'success')
        return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

def create_test_user():
    if not User.query.filter_by(email='test@example.com').first():
        hashed_password = generate_password_hash('password123')
        user = User(username='testuser', email='test@example.com', password=hashed_password)
        db.session.add(user)
        db.session.commit()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_test_user()
    app.run(debug=True)