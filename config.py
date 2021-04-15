import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
        #SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
        SECRET_KEY = 'hard to guess string' 
        SQLALCHEMY_COMMIT_ON_TEARDOWN = True
        MAIL_SERVER = 'mail.efun.com'
        MAIL_PORT = 25
        MAIL_USE_TLS = True
        MAIL_USERNAME = 'xxxx@qq.com'
        MAIL_PASSWORD = 'xxxx'
        FLASKY_MAIL_SUBJECT_PREFIX = '[Monitor]'
        FLASKY_MAIL_SENDER = 'Flasky Admin <wenyx-it@efun.com>'
	FLASKY_ADMIN = 'wenyx-it@efun.com'

    	@staticmethod
	def init_app(app):
		pass

class DevelopmentConfig(Config):
	SQLALCHEMY_DATABASE_URI = 'mysql://root:xxxxx@localhost/monitor_v1'
	SQLALCHEMY_TRACK_MODIFICATIONS = 'False'

#class TestingConfig(Config):
#	TESTING = True
#	SQLALCHEMY_DATABASE_URI = 'mysql://root:''@localhost:3306/test_monitor'
#	SQLALCHEMY_TRACK_MODIFICATIONS = 'False'

#class ProductionConfig(Config):
#	SQLALCHEMY_DATABASE_URI = 'mysql://root:''@localhost:3306/data_monitor'
#	SQLALCHEMY_TRACK_MODIFICATIONS = 'False'

config = {
#	'development': DevelopmentConfig,
#	'testing': TestingConfig,
#	'production': ProductionConfig,
	'default': DevelopmentConfig
}

