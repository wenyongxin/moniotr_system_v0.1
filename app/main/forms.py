#ecoding:utf-8

from flask.ext.wtf import Form
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, SelectField, ValidationError, PasswordField, SelectMultipleField
from wtforms.validators import DataRequired, Length, Email, Regexp, IPAddress
from ..models import User, Role

class NameForm(Form):
    name = StringField('what is your name?', validators=[DataRequired()])
    submit = SubmitField('Submit')

class EditProfileForm(Form):
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

class EditProfileAdminForm(Form):
    email = StringField('Email', validators=[DataRequired(), Length(1,64), Email()])
    username = StringField('Username', validators=[
        DataRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 
                                              'Username must have only letters, '
                                              'numbers, dots or underscores')])
    confirmed = BooleanField('Confirmed')
    role = SelectField(u'角色', coerce=int)
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=feild.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


ports = [('22', '22'), ('20755', '20755'), ('36000', '36000')]
proxys = [('103.227.128.16', u'香港'),
                                ('58.229.180.29', u'韩国'),
                                ('218.32.219.148', u'远传'),
                                ('54.207.73.140', u'美洲'),
                                ('54.93.169.149', u'欧洲'),
                                ('203.69.109.117', u'中华'),
                                ('175.41.130.249', u'新加坡'),
                                ('119.29.137.171', u'腾讯云')
                             ]
systems = [('c', 'Centos'), ('u', 'Ubuntu'), ('f', 'Freebsd'), ('s', 'Suse'), ('d', 'Debian')]




class AddMachineForm(Form):
    port = SelectField(u"SSH端口号")
    password = StringField(u"SSH密码", validators=[DataRequired()])
    submit = SubmitField(u"开始安装")
    def __init__(self, *args, **kwargs):
        super(AddMachineForm, self).__init__(*args, **kwargs)
	self.port.choices = ports 


class CheckMachineForm(Form):
    ip = StringField(u"主机地址")
    proxy = SelectField(u"Proxy列表")
    system = SelectField(u"System列表")
    submit = SubmitField(u"检测并安装")

    def __init__(self, *args, **kwargs):
        super(CheckMachineForm, self).__init__(*args, **kwargs)
        self.proxy.choices = proxys 
        self.system.choices = systems



class InsertZabbixInfo(Form):
	zabbix_ip = StringField(u"zabbix IP地址")
	zabbix_user = StringField(u"zabbix 用户")
	zabbix_password = PasswordField(u'zabbix 密码', validators=[DataRequired()])
	zabbix_submit = SubmitField(u"提交")


