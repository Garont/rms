import os
from datetime import date
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    DOMAIN_NAME = "rms.example.com"
    COPYRIGHT_YEAR = str(date.today().year)
    CSRF_ENABLED = True
    SECRET_KEY = ''

    DBNAME = 'rms'
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqldb://rms:<pass>@localhost/'+DBNAME
    SQLALCHEMY_DATABASE_CREATION_URI = 'mysql+mysqldb://rms:<pass>@localhost/'
    SQLALCHEMY_POOL_RECYCLE = 600
    SQLALCHEMY_POOL_SIZE = 5
    SQLALCHEMY_POOL_TIMEOUT = 15
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # mail server settings
    MAIL_SERVER = 'mail.example.com'
    MAIL_PORT = 465
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_USERNAME = 'rms@examole.com'
    MAIL_PASSWORD = '<pass>'
    MAIL_DEBUG = False
    # MAIL_DEFAULT_SENDER = None
    # MAIL_MAX_EMAILS = None
    # MAIL_SUPPRESS_SEND = app.testing
    # MAIL_ASCII_ATTACHMENTS = False

    # administrators list
    ADMINS = ['test@example.com',]
    # pagination
    #POSTS_PER_PAGE = 3

    #caching
    CACHE_TYPE = 'simple'
    HASHHIDS_SALT = "<mysalt>"
    LOG_FILE = basedir+u'/logs/rms.log'
