#-*- coding=utf-8 -*-
from . import db
from flask.ext.login import UserMixin, AnonymousUserMixin
from . import login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from datetime import datetime

class Permission(object):
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')
     
    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES |
                     Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %s>' % self.name

class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False
    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password = db.Column(db.String(128))
    role_permissions = db.Column(db.Boolean, default=False) 
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.now)
    last_seen = db.Column(db.DateTime(), default=datetime.now)
    #赋予角色   
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
    #角色验证
    def can(self, permissions):
        return self.role is not None and \
            (self.role.permissions & permissions) == permissions
    def is_administrator(self):
        return self.can(Permission.ADMINISTER)
    #密码验证
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    #刷新用户的最后访问时间
    def ping(self):
        self.last_seen = datetime.now()
        db.session.add(self)

    #邮件验证校对token
    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True
  
    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})

    def reset_password(self, token, password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('reset') != self.id:
            return False
        self.password = password
        db.session.add(self)
        return True 
    
    def generate_resetemail_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'email': self.id, 'new_email': new_email})

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        db.session.add(self)
        return True    
          

    def __repr__(self):
        return '<User %s>' % self.username

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Machine(db.Model):
    __tablename__ = "machine"
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64))
    port = db.Column(db.Integer)
    proxy = db.Column(db.String(64))
    system = db.Column(db.String(64))
    password = db.Column(db.String(64))
    monitor = db.Column(db.Boolean, default=False)
    i_time = db.Column(db.DateTime(), default=datetime.now)
    i_user = db.Column(db.String(64))
    data = db.Column(db.Text(65535))

    def __repr__(self):
        return '<Machine %s>' % self.ip

class ZabbixInfo(db.Model):
    __tablename__ = "zabbixinfo"
    id = db.Column(db.Integer, primary_key=True)
    zabbix_server = db.Column(db.String(64), unique=True)
    zabbix_user = db.Column(db.String(64))
    zabbix_password = db.Column(db.String(64))
    zabbix_info = db.Column(db.String(64))

    def __repr__(self):
	return '<ZabbixInfo %s>' % self.zabbix_server


class ReportDns(db.Model):
    __tablename__ = "report_dns"
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(64))
    domain_name = db.Column(db.String(64))
    domain_type = db.Column(db.String(64))
    domain_add = db.Column(db.String(64))
    operation = db.Column(db.String(64))
    game_name = db.Column(db.String(64))
    game_lange = db.Column(db.String(64))
    game_static = db.Column(db.String(64))

    def __repr__(self):
        return '<ReportDns %s>' % self.domain_name


class ReportFileInfo(db.Model):
	__tablename__="report_file_info"
	id = db.Column(db.Integer, primary_key=True)
    	generate_time = db.Column(db.DateTime(), default=datetime.now)
	operation_user = db.Column(db.String(64))
	file_form = db.Column(db.String(64))
	file_name = db.Column(db.String(64))
	
	def __repr__(self):
		return '<ReportFileInfo %s>' % self.file_name

class SpecialPort(db.Model):
	__tablename__="special_port"
	id = db.Column(db.Integer, primary_key=True)
	port = db.Column(db.String(64))
	
	def __repr__(self):
		return '<SpecialPort %s>' % self.port
	
	
	
class ScanGroup(db.Model):
	__tablename__="scan_group"
	id = db.Column(db.Integer, primary_key=True)
	hostname = db.Column(db.String(64))
	hostgroupid = db.Column(db.String(64))
	ipaddr = db.Column(db.String(64))
	hostid = db.Column(db.String(64))
	i_time = db.Column(db.DateTime(), default=datetime.now)
	operation_user = db.Column(db.String(64))
	progress = db.Column(db.Boolean, default=False)
	data = db.Column(db.Text(65535))

	def __repr__(self):
		return '<ScanGroup %s>' % self.hostname


class OpenVAS(db.Model):
	__tablename__="openvas_report"
	id = db.Column(db.Integer, primary_key=True)
	hostname = db.Column(db.String(64))
	hostgroupid = db.Column(db.String(64))
	ipaddr = db.Column(db.String(64))
	hostid = db.Column(db.String(64))
	i_time = db.Column(db.DateTime(), default=datetime.now)
	operation_user = db.Column(db.String(64))
	progress = db.Column(db.Boolean, default=False)
	data = db.Column(db.Text(65535))
	scan_id = db.Column(db.Text(65535))
	target_id = db.Column(db.Text(65535))
	plan = db.Column(db.String(64))

	def __repr__(self):
		return '<OpenVAS %s>' % self.hostname


class En_To_Cn(db.Model):
	__tablename__="openvas_en2cn"
	id = db.Column(db.Integer, primary_key=True)
	en = db.Column(db.Text(65535))
	cn = db.Column(db.Text(65535))

	def __repr__(self):
		return '<En_To_Cn %s>' % self.en


class ReportFault(db.Model):
	__tablename__="report_fault"
	id = db.Column(db.Integer, primary_key=True)
	fault_date = db.Column(db.DateTime())
	fault_describe = db.Column(db.Text(65535))
	fault_range = db.Column(db.String(64))
	fault_impact_time = db.Column(db.String(64))
	fault_user_experience = db.Column(db.Boolean, default=False)
	fault_affect_user = db.Column(db.String(64))
	fault_economic_losses = db.Column(db.String(64))
	fault_data_form = db.Column(db.String(64))
	fault_core_business = db.Column(db.Boolean, default=False)
	fault_business_module = db.Column(db.String(64))
	fault_operations_center = db.Column(db.String(64))
	fault_type = db.Column(db.String(64))
	fault_head = db.Column(db.String(64))
	fault_attribution = db.Column(db.String(64))
	fault_status = db.Column(db.Boolean, default=False)
	fault_cause_problem = db.Column(db.Text(65535))
	fault_clusion = db.Column(db.Text(65535))
	fault_improve = db.Column(db.Text(65535))
	fault_app_type = db.Column(db.String(64))
	fault_month = db.Column(db.String(64))

	def __repr__(self):
		return '<ReportFault %s>' % self.fault_describe 

class FaultOperationsCenter(db.Model):
	__tablename__="fault_operations_center"
	id = db.Column(db.Integer, primary_key=True)
	fcenter = db.Column(db.String(64))

	def __repr__(self):
		return '<FaultOperationsCenter %s>' % self.fcenter	



class FaultType(db.Model):
	__tablename__="fault_type"
	id = db.Column(db.Integer, primary_key=True)
	ftype = db.Column(db.String(64))
	
	def __repr__(self):
		return '<FaultType %s>' % self.ftype


class FaultAttribution(db.Model):
	__tablename__="fault_attribution"
	id = db.Column(db.Integer, primary_key=True)
	fattribution = db.Column(db.String(64))

	def __repr__(self):
		return '<FaultAttribution %s>' %self.fattribution


class MonitorFile(db.Model):
        __tablename__="monitor_file"
        id = db.Column(db.Integer, primary_key=True)
        generate_time = db.Column(db.DateTime(), default=datetime.now)
        operation_user = db.Column(db.String(64))
        file_name = db.Column(db.String(64))

        def __repr__(self):
                return '<MonitorFile %s>' % self.file_name

class ManagerDns(db.Model):
	__tablename__="manager_dns"
	id = db.Column(db.Integer, primary_key=True)
	dns_domain = db.Column(db.String(64))
	dns_supplier = db.Column(db.String(64))
	dns_url = db.Column(db.String(64))
	dns_date_end = db.Column(db.String(64))
	dns_info = db.Column(db.Text(65535))

	def __repr__(self):
		return '<ManagerDns %s>' % self.dns_supplier

class Traffic_Summary(db.Model):
	__tablename="traffic_summary"
	id = db.Column(db.Integer, primary_key=True)
	time = db.Column(db.String(64)) 
	idc_hostgroupid = db.Column(db.String(64))
	game_hostgroupid = db.Column(db.String(64))
	out_value = db.Column(db.String(64))
	in_value = db.Column(db.String(64))

	def __repr__(self):
		return '<Traffic_Summary %s>' % self.id


class Ssh_History(db.Model):
	__tablename__="ssh_history"
	id = db.Column(db.Integer, primary_key=True)
	user = db.Column(db.String(64))
	date = db.Column(db.DateTime(), default=datetime.now)
	history = db.Column(db.Text(65535))

	def __repr__(self):
		return '<Ssh_History %s>' % self.id

class Game_Distribution(db.Model):
	__tablename__="game_distribution"
	id = db.Column(db.Integer, primary_key=True)
	center = db.Column(db.String(64))
	gamename = db.Column(db.String(64))
	first_name = db.Column(db.String(64))
	first_phone = db.Column(db.String(64))
	second_name = db.Column(db.String(64))
	second_phone = db.Column(db.String(64))
	third_name = db.Column(db.String(64))
	third_phone = db.Column(db.String(64))
	vendor = db.Column(db.String(64))
	operations = db.Column(db.String(64))
	online = db.Column(db.String(64))
	PMname = db.Column(db.String(64))
	
	def __repr__(self):
		return '<Game_Distribution %s>' % self.id


