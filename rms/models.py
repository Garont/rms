import hashlib
from random import randint
from datetime import datetime
from rms import rms, db
from werkzeug import generate_password_hash, check_password_hash
from flask_permissions.models import UserMixin, Role
from sqlalchemy.sql import text

class SimpleSql():
    def sql(self, req, reply=True):
        if not reply:
            db.engine.execute(text(req).execution_options(autocommit=True))
        else:
            result = db.engine.execute(text(req).execution_options(autocommit=True))

            ret = []
            for row in result:
                ret.append(dict(row))
            return ret

class User(UserMixin):
    __tablename__ = "fp_user"
    __table_args__ = {'extend_existing' : True}
    login = db.Column('login', db.String(120), unique=True, index=True)
    pwdhash = db.Column('pwdhash',db.String(100))

    def __init__(self, login, password, roles=None):
        self.login = login
        self.set_password(password)
        UserMixin.__init__(self, roles)


    def set_password(self, password):
        self.pwdhash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.pwdhash, password)

    def __str__(self):
        return self.login

    def __repr__(self):
        return "<User(id='%s', login='%s', pwdhash='%s')>" % (self.id, self.login, self.pwdhash)


class Tasks(db.Model):
    __tablename__ = 'tasks'
    __table_args__ = {'extend_existing' : True}
    uid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    hostname = db.Column(db.String(100))
    jobname = db.Column(db.String(100))
    port = db.Column(db.Integer, default = 22)
    secret = db.Column(db.String(10000), default = '')
    script = db.Column(db.String(50000))
    sec = db.Column(db.String(20))
    min = db.Column(db.String(20))
    hour = db.Column(db.String(20))
    day = db.Column(db.String(20))
    week = db.Column(db.String(20))
    dow = db.Column(db.String(20))
    month = db.Column(db.String(20))
    enabled = db.Column(db.Boolean)
    creation_date = db.Column(db.DateTime, default = datetime.utcnow)
    last_launch = db.Column(db.DateTime, default = 0)
    last_success_launch = db.Column(db.DateTime, default = 0)
    exit_status = db.Column(db.Integer, default = 0)

    def __init__(self, task_username, task_hostname, task_jobname, task_port, task_secret, task_script,
     task_sec, task_min, task_hour, task_day, task_week, task_dow, task_month, task_isactive, last_launch, last_success_launch, exit_status):
        self.username = task_username
        self.hostname = task_hostname
        self.jobname = task_jobname
        self.port = task_port
        self.secret = task_secret
        self.script = task_script
        self.sec = task_sec
        self.min = task_min
        self.hour = task_hour
        self.day = task_day
        self.week = task_week
        self.dow = task_dow
        self.month = task_month
        self.enabled = task_isactive
        self.last_launch = last_launch
        self.last_success_launch = last_success_launch
        self.exit_status = exit_status

    def __repr__(self):
        return "<Tasks(uid='%s', username='%s', hostname='%s', jobname='%s', port='%s', secret='%s', script='%s',\
         sec='%s', min='%s', hour='%s', day='%s', week='%s', dow='%s', month='%s',\
          creation_date='%s', last_launch='%s', last_success_launch='%s', exit_status='%s')>" % (
                       self.uid, self.username, self.hostname, self.jobname, self.port, self.secret, self.script, 
                       self.sec, self.min, self.hour, self.day, self.week, self.dow, self.month,
                       self.creation_date, self.last_launch, self.last_success_launch, self.exit_status)


class OldTasks(db.Model):
    __tablename__ = 'old_tasks'
    __table_args__ = {'extend_existing' : True}
    uid = db.Column(db.Integer, primary_key=True)
    tid = db.Column(db.Integer)
    username = db.Column(db.String(100))
    hostname = db.Column(db.String(100))
    jobname = db.Column(db.String(100))
    port = db.Column(db.Integer)
    secret = db.Column(db.String(10000))
    script = db.Column(db.String(50000))
    sec = db.Column(db.String(20))
    min = db.Column(db.String(20))
    hour = db.Column(db.String(20))
    day = db.Column(db.String(20))
    week = db.Column(db.String(20))
    dow = db.Column(db.String(20))
    month = db.Column(db.String(20))
    changing_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, tid, task_username, task_hostname, task_jobname, task_port, task_secret, task_script,
     task_sec, task_min, task_hour, task_day, task_week, task_dow, task_month):
        self.tid = tid
        self.username = task_username
        self.hostname = task_hostname
        self.jobname = task_jobname
        self.port = task_port
        self.secret = task_secret
        self.script = task_script
        self.sec = task_sec
        self.min = task_min
        self.hour = task_hour
        self.day = task_day
        self.week = task_week
        self.dow = task_dow
        self.month = task_month


    def __repr__(self):
        return "<OldTasks(uid='%s', tid='%s', username='%s', hostname='%s', jobname='%s', port='%s', secret='%s', script='%s',\
         sec='%s', min='%s', hour='%s', day='%s', week='%s', dow='%s', month='%s', changing_date='%s')>" % (
                       self.uid, self.tid, self.username, self.hostname, self.jobname, self.port, self.secret, self.script, 
                       self.sec, self.min, self.hour, self.day, self.week, self.dow, self.month, self.changing_date)


