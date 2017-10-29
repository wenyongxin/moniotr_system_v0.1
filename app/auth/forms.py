#ecoding:utf-8
from flask.ext.wtf import Form
from wtforms import StringField, SubmitField, BooleanField, PasswordField, ValidationError
from wtforms.validators import Length, Email, DataRequired, Regexp, EqualTo
from ..models import User

class LoginForm(Form):
	email = StringField(u'用户名', validators=[DataRequired(), Length(1, 64), Email()])
	password = PasswordField(u'密码', validators=[DataRequired()])
	remember_me = BooleanField(u'记住密码')
	submit = SubmitField(u'登录')

class RegistrationForm(Form):
	email = StringField(u'邮箱地址', validators=[DataRequired(), Length(1, 64), Email()])
	username = StringField(u'姓名', validators=[DataRequired()])
	password = PasswordField(u'密码', validators=[DataRequired(), EqualTo('password2', message=u'确认密码必须相同')])
	password2 = PasswordField(u'确认密码', validators=[DataRequired()])
	submit = SubmitField(u'完成')

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError(u'电子邮件已经注册')

	def validate_username(self, field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError(u'电子邮件已经注册')

class ChangePasswordForm(Form):
	password = PasswordField(u'旧密码', validators=[DataRequired()])
	password2 = PasswordField(u'新密码', validators=[DataRequired(), EqualTo('password3', message=u"确认密码必须相同")])
	password3 = PasswordField(u'确认密码', validators=[DataRequired()])
	submit = SubmitField(u'提交')

class ResetPasswordRequstForm(Form):
	email = StringField(u'邮箱地址', validators=[DataRequired(), Length(1, 64), Email()])
	submit = SubmitField(u'提交')

class ResetPasswordForm(Form):
	email = StringField(u'邮箱地址', validators=[DataRequired(), Length(1, 64), Email()])
	password = PasswordField(u'新密码', validators=[DataRequired(), EqualTo('password2', message=u"密码不匹配")])
	password2 = PasswordField(u'确认密码', validators=[DataRequired()])
	submit = SubmitField(u'提交')

class ChangeEmailForm(Form):
	email = StringField(u'新邮箱地址', validators=[DataRequired(), Length(1, 64), Email()])
	password = PasswordField(u'密码', validators=[DataRequired()])
	submit = SubmitField(u'提交')
