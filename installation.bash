#!/bin/bash
if ! env | grep VIRTUAL_ENV &> /dev/null ; then echo "run directy from venv!" ;exit 1; fi
apt-get install librrd-dev libmysqld-dev python-dev
pip install flask Flask-Cache Flask-SQLAlchemy flask-csrf flask-wtf flask-wtf-alchemy-utils simple_openid rrdtool mysql fabric_deploy hashids celery apscheduler email paramiko Flask-Mail gevent flask_restful flask-permissions flask-login Flask-Script
