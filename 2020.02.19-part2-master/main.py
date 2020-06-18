import os

from flask import Flask, render_template, redirect
from flask_login import LoginManager
from models import db_session
from models.users import User, RegisterForm, LoginForm
from flask_restful import abort


app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
db_session.global_init('sqlite.db')
login_manager = LoginManager()
login_manager.init_app(app)

f = False
men_page, reg, adm, rig = None, None, None, None


@app.route("/")
def home():
    global f, adm, men_page
    return render_template('Hello.html', flag=f, admi=adm, men=men_page)


@app.route("/content")
def content():
    return render_template('content.html', flag=f)


@app.route("/Osnova")
def Osnova():
    global f
    return render_template('Osnova.html', flag=f)


@app.route("/Знакомство со средой")
def Знакомство_со_средой():
    global f
    if f:
        return render_template('book/Знакомство со средой.html', flag=f)
    else:
        abort(403)


@app.route("/Простые встроенные функции")
def Простые_встроенные_функции():
    global f
    if f:
        return render_template('book/Простые встроенные функции.html', flag=f)
    else:
        abort(403)


@app.route("/Знакомство с циклами")
def Знакомство_с_циклами():
    global f
    if f:
        return render_template('book/Знакомство с циклами.html', flag=f)
    else:
        abort(403)


@app.route("/Знакомство со списками и словарями")
def Знакомство_со_списками_и_словарями():
    global f
    if f:
        return render_template('book/Знакомство со списками и словарями.html', flag=f)
    else:
        abort(403)


@app.route("/Функции")
def Функции():
    global f
    if f:
        return render_template('book/Функции.html', flag=f)
    else:
        abort(403)


@app.route("/Admin")
def admin():
    session = db_session.create_session()
    return render_template(
        'bases/admin.html',
        User=session.query(User).order_by(User.date.desc())
    )


@app.route("/Admin_bd")
def Admin_bd():
    session = db_session.create_session()
    return render_template(
        'bases/Admin_bd.html',
        User=session.query(User).order_by(User.date.desc())
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    global f, men_page, reg, adm, rig
    if not f or rig:
        reg = True
        form = LoginForm()
        if form.validate_on_submit():
            if form.login.data == 'admin':
                if form.password.data == '123':
                    f, adm = True, True
                    rig = None
                    session = db_session.create_session()
                    return render_template(
                        'bases/admin.html',
                        User=session.query(User).order_by(User.date.desc())
                    )
                else:
                    return render_template("Error/Admin_error.html", flag=f, admi=adm, men=men_page)

            session = db_session.create_session()
            if session.query(User).filter(User.login == form.login.data).first():
                user = session.query(User).filter(User.login == form.login.data).first()
                if user and user.check_password(form.password.data):
                    f = True
                    rig = None
                    return render_template('Osnova.html', flag=f, men=men_page)
                else:
                    return render_template('reg_and_log/login.html', title='Регистрация',
                                           log=True,
                                           form=form,
                                           reg=reg,
                                           message="Не правильный пароль")
            else:
                return render_template('reg_and_log/login.html', title='Регистрация',
                                       log=True,
                                       form=form,
                                       reg=reg,
                                       message="Такого пользователя нету в базе данных, может зарегистрируешься?")

        return render_template('reg_and_log/login.html', title='Авторизация', form=form, reg=reg)
    else:
        abort(401)


@app.route('/register', methods=['GET', 'POST'])
def register():
    global f, reg, rig
    reg = False
    if not rig:
        form = RegisterForm()
        if form.validate_on_submit():
            if form.password.data != form.password_again.data:
                return render_template('reg_and_log/register.html', title='Регистрация',
                                       form=form,
                                       reg=reg,
                                       message="Пароли не совпадают")

            session = db_session.create_session()
            if session.query(User).filter(User.login == form.login.data).first():
                return render_template('reg_and_log/register.html', title='Регистрация',
                                       form=form,
                                       reg=reg,
                                       message="Такой пользователь уже есть")
            if form.login.data == 'adminrys':
                return render_template('reg_and_log/register.html', title='Регистрация',
                                       form=form,
                                       reg=reg,
                                       message="Извините, но этот логин занят админом :)")
            if len(form.password.data) < 5 and len(form.login.data) < 5:
                return render_template('reg_and_log/register.html', title='Регистрация',
                                       form=form,
                                       reg=reg,
                                       message="Логин и пароль должны быть больше 5 символов")

            if len(form.password.data) < 5:
                return render_template('reg_and_log/register.html', title='Регистрация',
                                       form=form,
                                       reg=reg,
                                       message="Пароль слишком короткий, он должны быть больше 5 символов")
            if len(form.login.data) < 5:
                return render_template('reg_and_log/register.html', title='Регистрация',
                                       form=form,
                                       reg=reg,
                                       message="Логин слишком короткий, он должны быть больше 5 символов")
            user = User(
                login=form.login.data,
                hashed_password=form.password.data
            )
            user.set_password(form.password.data)
            session.add(user)
            session.commit()
            f, rig = True, True
            return redirect('/login')
        return render_template('reg_and_log/register.html', title='Регистрация', form=form, reg=reg)
    else:
        abort(404)


@app.route('/delete_log', methods=['GET', 'POST'])
def delete_log():
    global f, men_page
    f = False
    men_page = None
    return render_template('Osnova.html', flag=f, admi=False)


@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)