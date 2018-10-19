from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, logout_user, current_user

from app import db
from app.auth import auth
from app.auth.forms import LoginForm, RegistrationForm, ChangePWForm, ResetPWRequestForm, ResetPWForm
from app.models import User

from ..email import send_mail


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.index')
            return redirect(next)
        flash('Invalid username or password')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/changePW', methods=['GET', 'POST'])
@login_required
def changePW():
    form = ChangePWForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.original.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            db.session.commit()
            flash("Your password has been updated.")
            return redirect(url_for('main.index'))
        else:
            flash("Invalid password.")
    return render_template('auth/changePW.html', form=form)


@auth.route('/reset', methods=['GET', 'POST'])
def resetPW_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = ResetPWRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_mail(user.email, 'Reset Password', 'auth/email/resetPW',
                      user=user, token=token)
        flash('An email with instructions to reset your password has been '
              'sent to you.')
        return redirect(url_for('auth.login'))
    return render_template('auth/resetPW.html', form=form)


@auth.route('/reset/<token>', methods=['GET', 'POST'])
def resetPW(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = ResetPWForm()
    if form.validate_on_submit():
        if User.confirm_reset(token, form.password.data):
            db.session.commit()
            flash("Your password has been updated")
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/resetPW.html', form=form)


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_reset_token()
        send_mail(user.email, 'Confirm Your Account',
                  'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        db.session.commit()
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired')
    return redirect(url_for('main.index'))


@auth.before_app_request
def before_request():
    if current_user.is_authenticated \
            and not current_user.confirmed \
            and request.blueprint != 'auth' \
            and request.endpoint != "static":
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
    send_mail(current_user.email, 'Confirm Your Account',
              'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))