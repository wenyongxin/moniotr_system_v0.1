#!/usr/bin/env python
import os
from app import create_app, db
from app.models import User, Role
from flask.ext.script import Manager, Shell, Server
from flask.ext.migrate import Migrate, MigrateCommand

app = create_app('default')
app.secret_key = 'abcdef'
manager = Manager(app)
migrate = Migrate(app, db)
app.secret_key = 'abcdef'

def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role)
manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)
manager.add_command('runserver', Server( host = '0.0.0.0', port = 5200, use_debugger = True))


if __name__ == "__main__":
    #socketio.run(app)
#    manager.run()
	app.run(host='0.0.0.0')
