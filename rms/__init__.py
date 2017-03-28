import os
import datetime
from flask import Flask
# from flask.ext.cache import Cache 
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import sessionmaker
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, current_user, AnonymousUserMixin
from flask_permissions.core import Permissions
from flask_mail import Mail
from .momentjs import momentjs
from flask_openid import OpenID
from config import Config
import rrdtool
import logging
from pytz import utc
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.pool import ThreadPoolExecutor, ProcessPoolExecutor

rms = Flask(__name__)
rms.config.from_object('config.Config')


jobstores = {
    'default': SQLAlchemyJobStore(url=rms.config['SQLALCHEMY_DATABASE_URI'])
}
executors = {
    'default': ThreadPoolExecutor(30),
    'processpool': ProcessPoolExecutor(10)
}
job_defaults = {
    'coalesce': False,
    'max_instances': 10
}
scheduler = BackgroundScheduler(jobstores=jobstores, executors=executors, job_defaults=job_defaults, timezone=utc)
scheduler.start()

rms.jinja_env.globals['momentjs'] = momentjs
db = SQLAlchemy(rms)
Session = sessionmaker()
# cache = Cache(rms)
csrf = CSRFProtect(rms)
mail = Mail(rms)
csrf.init_app(rms)
db.init_app(rms)

perms = Permissions(rms, db, current_user)
login_manager = LoginManager()
login_manager.init_app(rms)

#auth
#http://pythonhosted.org/Flask-Principal/
#http://flask-restful-cn.readthedocs.org/en/0.3.4/quickstart.html

def setup_logger(logger_name, log_file, level=logging.INFO):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(asctime)s : %(message)s')
    fileHandler = logging.FileHandler(log_file, mode='a')
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)

    l.setLevel(level)
    l.addHandler(fileHandler)
    l.addHandler(streamHandler)    

from rms import views, models
from models import User


db.create_all()
db.session.commit()


is_any_user_in_db = db.session.query(User).first()
if is_any_user_in_db:
    pass
else:
    first_run_create_admin = User(login="admin", password="admin", roles=["admin","api"])
    db.session.add(first_run_create_admin)
    db.session.commit()



