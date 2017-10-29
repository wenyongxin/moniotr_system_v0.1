#ecoding:utf-8
from flask import render_template, redirect, url_for, request, flash, current_app
from . import auth
from .forms import LoginForm, RegistrationForm, ChangePasswordForm, ResetPasswordRequstForm, ResetPasswordForm, ChangeEmailForm
from ..models import User, db
from flask.ext.login import login_user, logout_user, login_required, current_user
from ..email import send_email
from ..decorators import admin_required, permission_required

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash(u'无效的用户名密码')
    return render_template('login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET','POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm your acoount','auth/email/confirm', user=user, token=token)
        flash((u'邮件已发到%s邮箱请登录确认' %form.email.data))
        return redirect(url_for('main.index')) 
    return render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash(u'已经验证成功,请登录')
    else:
        flash(u'无效的邮箱验证')
    return redirect(url_for('main.index'))

@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                  and request.endpoint[:5] != 'auth.' \
                  and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')

@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, "Confirm your account", 'auth/email/confirm', user=current_user, token=token)
    flash(u'邮件已经发到你的邮箱')
    return redirect(url_for('main.index'))

@auth.route('/changepassword', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            current_user.password = form.password2.data
            db.session.add(current_user)
            db.session.commit()
        else:
            flash(u'密码错误')
        flash(u'请更改密码')
    return render_template('auth/passwordchange.html', form=form)

@auth.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = ResetPasswordRequstForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password', 'auth/email/reset', user=user, token=token, next=request.args.get('next'))
        flash(u'重置密码的邮件已发到你的邮箱')
        return redirect(url_for('auth.login'))
    return render_template('auth/resetpassword.html', form=form)

@auth.route('/reset/<token>', methods=['GET', 'POST'])
def reset_pass_confirm(token):
    form = ResetPasswordForm()
    if form.validate_on_submit(): 
        user = User.query.filter_by(email=form.email.data).first()
        print user
        if user is None:
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            flash('Your password is update.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/resetpassword.html', form=form)

@auth.route('/change-email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        new_email = form.email.data
        if new_email is not None and current_user.verify_password(form.password.data):
            token = current_user.generate_resetemail_token(new_email)
            send_email(new_email, 'Change your regist email.', 'auth/email/changeemail', user=current_user, token=token)
            flash(u'确认电子邮件已发发给你')
            return redirect(url_for('main.index'))
        else:
            flash(u'无效的邮箱或密码')
    return render_template('auth/changeemail.html', form=form)

@auth.route('/change-email/<token>')
@login_required
def change_email(token):
    if current_user.change_email(token):
        flash(u'邮箱更改完成')
    else:
        flash(u'无效的邮箱地址')
    return redirect(url_for('main.index'))

