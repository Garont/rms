# -*- coding: utf-8 -*-
from flask import request, render_template, make_response, flash, Flask, current_app, abort, redirect, url_for, session, escape, g, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from flask_permissions.decorators import user_is, user_has
from wtforms.validators import DataRequired, Email
from wtforms import TextField, PasswordField
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import default_exceptions
from werkzeug.exceptions import HTTPException
from flask_wtf import Form
from models import db, Tasks, OldTasks, User, UserMixin, SimpleSql, Role
from sqlalchemy.orm import query, aliased, session as sess
import sqlalchemy, re, base64
from pagination import Pagination
from rms import rms, db, scheduler, logging, mail, setup_logger, perms, login_manager
from flask_restful import Api, Resource
from flask_mail import Message
from .decorators import async
from random import randrange, choice
import paramiko
import string
from datetime import datetime
from hashids import Hashids
import urllib2

def urlencode(s):
    return urllib2.quote(s)

def urldecode(s):
    return urllib2.unquote(s).decode('utf8')


#setup loggers 
setup_logger('apscheduler.executors.default', rms.config['LOG_FILE'], logging.ERROR)
log_aps = logging.getLogger('apscheduler.executors.default')

setup_logger('deflog', rms.config['LOG_FILE'])
log = logging.getLogger('deflog')
#end setup loggers 

hashids = Hashids()

commons = { 
            'domain_name' : rms.config['DOMAIN_NAME'],
            'copyright_year' : rms.config['COPYRIGHT_YEAR'],
          }

#SETUP LOGIN
@rms.before_request
def before_request():
    g.user = current_user

@login_manager.user_loader
def get_user(ident):
  return User.query.get(int(ident))


@login_manager.request_loader
def load_user_from_request(request):
    # TODO: login using the api_key url arg
    # api_key = request.args.get('api_key')
    # if api_key:
    #     user = User.query.filter_by(api_key=api_key).first()
    #     if user:
    #         return user
    # Basic Auth
    api_key = request.headers.get('Authorization')
    if api_key:
        api_key = api_key.replace('Basic ', '', 1)
        try:
            api_key = base64.b64decode(api_key)
            logpass = api_key.split(':')
        except TypeError:
            pass
        registered_user = User.query.filter_by(login=logpass[0]).first()
        if registered_user and check_password_hash(registered_user.pwdhash, logpass[1]):
            return registered_user

    return None
#END LOGIN SETUP
#ERROR HANDLERS
@rms.errorhandler(404)
@rms.route('/4O4', defaults={'error':404})
def page_not_found(error):

    #custom 404 for api
    if request.path.startswith('/api'):
        return jsonify({'error':'404 error'})

    resp = make_response(render_template('page_not_found.html', commons=commons), 404)
    resp.headers['X-Sad'] = '404'
    return resp

@rms.errorhandler(400)
def bad_request(error):
    return jsonify({'error':'400 error. Bad Request'})

@rms.errorhandler(500)
def crashhandler_url(e):
    log.error(e)
    return render_template('error500.html', e=e, commons=commons)
#END ERROR HANDLERS


@rms.route('/login',methods=['POST', 'GET'])
@login_manager.unauthorized_handler
def login():
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('main'))
        else:
            return render_template('login.html', commons=commons)

    if request.method == 'POST':
        login = request.form['username']
        password = request.form['password']
        registered_user = User.query.filter_by(login=login).first()
        if registered_user and check_password_hash(registered_user.pwdhash, password):
            login_user(registered_user)
            return redirect(request.args.get('next') or url_for('main'))
        else:
            flash('Username or Password is invalid' , 'error')
            return redirect(url_for('login'))


@rms.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login')) 


@rms.route('/admin', methods=['POST', 'GET'])
@login_required
@user_is('admin')
def admin_main():
    if request.method == 'GET':
        resp = make_response(render_template('admin.html', commons=commons))
        return resp

@rms.route('/admin/users', methods=['POST', 'GET'])
@login_required
@user_is('admin')
def admin_users():
    if request.method == 'POST':
        if request.values.get('formtype') == 'create_user':
            login = request.values.get('login')
            password = request.values.get('password')
            roles = request.values.get('roles').split(",")

            user_exists = User.query.filter_by(login=login).first()
            if user_exists:
                db.session.delete(user_exists)
                db.session.commit()
                user_exists = User(login=login, password=password, roles=roles)
                db.session.add(user_exists)
                db.session.commit()
                print current_user.login,login
                if current_user.login == login:
                    login_user(user_exists)
            else:
                new_user = User(login=login, password=password, roles=roles)
                db.session.add(new_user)
                db.session.commit()
            return redirect(url_for('admin_users'))

        if request.values.get('formtype') == 'delete_users':
            delarr = request.values.getlist('check')
            for user in delarr:
                user = eval('['+user+']')
                print user
                for i in user:
                    print i
                userid = hashids.decrypt(user[0])
                login = user[1]
                roles = user[2]
                my_user = User.query.filter_by(login=login).first()
                my_user.remove_roles(roles)
                db.session.delete(my_user)
                db.session.commit()
                # userdel = SimpleSql().sql("DELETE FROM fp_user_role WHERE user_id = "+str(userid[0])+"; DELETE FROM fp_user WHERE id = "+str(userid[0])+";", reply=False)
            return redirect(url_for('admin_users'))

    if request.method == 'GET':
        # result = db.engine.execute(text("SELECT fp_user.login as fp_user, fp_role.name AS fp_role FROM fp_user_role \
        #     INNER JOIN fp_user ON fp_user_role.user_id = fp_user.id \
        #     INNER JOIN fp_role ON fp_role.id = fp_user_role.role_id ORDER BY fp_user;").execution_options(autocommit=True))
        users = SimpleSql().sql("SELECT fp_user.id, fp_user.login as fp_user, GROUP_CONCAT(fp_role.name) AS fp_role FROM fp_user_role \
            INNER JOIN fp_user ON fp_user_role.user_id = fp_user.id \
            INNER JOIN fp_role ON fp_role.id = fp_user_role.role_id GROUP BY fp_user.login;")

        for user in users:
            user['id'] = hashids.encrypt(int(user['id']))

        return render_template('users.html', users=users, commons=commons)

@rms.route('/admin/logs_purge')
@login_required
@user_is('admin')
def admin_logs_purge():
    open(rms.config['LOG_FILE'], 'w').close()
    return redirect(url_for('admin_logs'))

@rms.route('/logs')
@login_required
def admin_logs():
    ret = "<pre>"+open(rms.config['LOG_FILE'],'r').read()+"</pre>"
    return ret

def test_task(task_arr):
        select_regexp = re.compile('\*|[0-9][0-9]?')
        for index, item in enumerate(task_arr):
            if not select_regexp.match(item):
                task_arr[index] = None
        return task_arr

@rms.route('/getjobs')
@login_required
@user_is('admin')
def getjobs():
    return '[<br>%s<br>]' % ',<br>   '.join(map(str, scheduler.get_jobs()))

@rms.route('/remove_all_jobs')
@login_required
@user_is('admin')
def remove_all_jobs():
    scheduler.remove_all_jobs()
    return redirect(url_for('getjobs'))

@rms.route('/log_test')
@login_required
@user_is('admin')
def log_test():
    log.debug( u'This is a debug message' )
    log.info( u'This is an info message' )
    log.warning( u'This is a warning' )
    log.error( u'This is an error message' )
    log.critical( u'FATAL!' )

    return "log test"


@async
def send_async_email(msg):
    with rms.app_context():
        log.info(rms.config["ADMINS"])
        mail.send(msg)


def runner(uid = 0):
    task = Tasks.query.filter_by(uid = uid).first()

    log.info(u"Running Task: "+task.jobname)

    host = task.hostname
    user = task.username
    secret = task.secret
    port = int(task.port)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if secret and secret != '':
            client.connect(hostname=host, username=user, pkey=secret, port=port)
        else:
            client.connect(hostname=host, username=user, port=port)
        stdin, stdout, stderr = client.exec_command(task.script)
        data = stdout.read() + stderr.read()
        exit_status = stdout.channel.recv_exit_status()
        log.info(data)
        log.info("EXIT STATUS: "+str(exit_status))
        client.close()
        task.exit_status = exit_status
        nowtime = datetime.utcnow()
        task.last_launch = nowtime

        if exit_status == 0:
            task.last_success_launch = nowtime
        else:
            subject = "Task %s failed" % (task.jobname)
            content = "Task %s failed with error code %d\nTask Log:\n%s" % (task.jobname, exit_status, data)
            msg = Message(subject,
                      sender=(rms.config['DOMAIN_NAME'], rms.config['MAIL_USERNAME']+"@"+rms.config['MAIL_SERVER']),
                      recipients=rms.config['ADMINS']
                      )
            msg.body = content
            send_async_email(msg)

    except Exception as e:
        log_aps.error(str(e))
        log_aps.error("paramiko data: host:"+str(task.hostname)+" user:"+str(task.username)+" port:"+str(task.port)+" secret:"+str(task.secret))
        subject = "Task %s failed" % (task.jobname)
        content = "Task %s failed with paramikoException:\n%s" % (task.jobname, str(e))
        exit_status = 127
        task.exit_status = exit_status
        nowtime = datetime.utcnow()
        task.last_launch = nowtime
        msg = Message(subject,
                  sender=(rms.config['DOMAIN_NAME'], rms.config['MAIL_USERNAME']+"@"+rms.config['MAIL_SERVER']),
                  recipients=rms.config['ADMINS']
                  )
        msg.body = content
        send_async_email(msg)

    db.session.add(task)
    db.session.flush()
    db.session.commit()
    db.session.close()


@rms.route('/')
def main():
    all_tasks = Tasks.query.all()
    #pagination = Pagination(page=page, per_page=TASKS_PER_PAGE, total_count=tasks_count)
    encuids=[]
    for row in all_tasks:
            encuids.append(hashids.encrypt(int(row.uid)))

    return render_template('main.html', commons=commons, all_tasks=all_tasks, encuids=encuids)



@rms.route('/new', methods=['GET', 'POST'])
@login_required
def new():
    if request.method == 'POST':
        task_username = request.values.get('username')
        task_hostname = request.values.get('hostname')
        task_jobname = request.values.get('jobname')
        task_port = request.values.get('port')
        task_secret = request.values.get('secret')
        task_script = request.values.get('fabscript')
        task_sec = request.values.get('sec')
        task_min = request.values.get('min')
        task_hour = request.values.get('hour')
        task_day = request.values.get('day')
        task_week = request.values.get('week')
        task_dow = request.values.get('dayofweek')
        task_month = request.values.get('month')
        task_isactive = request.values.get('isactive') #None || "on"

        if not task_port:
            task_port = 22

        select_arr = [task_sec, task_min, task_hour, task_day, task_week, task_dow, task_month]

        select_arr = test_task(select_arr)
        task_sec = select_arr[0]
        task_min = select_arr[1]
        task_hour = select_arr[2]
        task_day = select_arr[3]
        task_week = select_arr[4]
        task_dow = select_arr[5]
        task_month = select_arr[6]

        if task_isactive == "on":
            task_isactive = True
        else: 
            task_isactive = False

        new_task = Tasks(task_username, task_hostname, task_jobname, task_port, task_secret, task_script, task_sec, task_min, task_hour, task_day, task_week, task_dow, task_month, 
                         task_isactive, last_launch = 0, last_success_launch=0, exit_status=0)

        db.session.add(new_task)

        if task_isactive:
            db.session.flush()
            scheduler.add_job(
                    runner, 
                    kwargs={'uid':new_task.uid}, 
                    trigger = 'cron', 
                    second = new_task.sec, minute = new_task.min , hour = new_task.hour, 
                    day = new_task.day, week = new_task.week, day_of_week = new_task.dow, month = new_task.month, year = None, 
                    id = str(new_task.uid)
                )

        db.session.commit()

        return redirect(url_for('new'))
    else:
        return render_template('new.html',commons=commons)




@rms.route('/edit', defaults={'tid': 0})
@rms.route('/edit/<tid>', methods=['POST', 'GET'])  
@login_required
@user_is('admin')
def edit(tid):
    get_id = hashids.decrypt(tid)

    if request.method == 'POST':
        task_username = request.values.get('username')
        task_hostname = request.values.get('hostname')
        task_jobname = request.values.get('jobname')
        task_port = request.values.get('port')
        task_secret = request.values.get('secret')
        task_script = request.values.get('fabscript')
        task_sec = request.values.get('sec')
        task_min = request.values.get('min')
        task_hour = request.values.get('hour')
        task_day = request.values.get('day')
        task_week = request.values.get('week')
        task_dow = request.values.get('dayofweek')
        task_month = request.values.get('month')
        task_isactive = request.values.get('isactive') #None || "on"

        select_arr = [task_sec, task_min, task_hour, task_day, task_week, task_dow, task_month]

        select_arr = test_task(select_arr)
        task_sec = select_arr[0]
        task_min = select_arr[1]
        task_hour = select_arr[2]
        task_day = select_arr[3]
        task_week = select_arr[4]
        task_dow = select_arr[5]
        task_month = select_arr[6]


        if task_isactive == "on":
            task_isactive = True
        else: 
            task_isactive = False

        task = Tasks.query.filter_by(uid=get_id).first()
        uid_str = str(task.uid)

        oldtask = OldTasks(task.uid, task.username, task.hostname, task.jobname, task.port, task.secret, 
                           task.script, task.sec, task.min, task.hour, task.day, task.week, task.dow, task.month) 
        db.session.add(oldtask)
        db.session.commit()     

        if scheduler.get_job(uid_str):
            scheduler.remove_job(uid_str)

        task.username = task_username
        task.hostname = task_hostname
        task.jobname = task_jobname
        task.port = task_port
        task.secret = task_secret
        task.script = task_script
        task.sec = task_sec
        task.min = task_min
        task.hour = task_hour
        task.day = task_day
        task.week = task_week
        task.dow = task_dow
        task.month = task_month
        task.enabled = task_isactive

        #task versioning     
        db.session.add(task)
        

        if not task_isactive:
            db.session.flush()
            if scheduler.get_job(uid_str):
                scheduler.remove_job(uid_str)
        else:
            if scheduler.get_job(uid_str):
                scheduler.remove_job(uid_str)
            scheduler.add_job(
                    runner,
                    kwargs = {'uid':task.uid},
                    trigger = 'cron',
                    second = task.sec, minute = task.min , hour = task.hour,
                    day = task.day, week = task.week, day_of_week = task.dow, month = task.month, year = None,
                    id = uid_str
                )

            if request.values.get('saveandrun'):
                scheduler.add_job(
                    runner,
                    kwargs = {'uid':task.uid},
                    run_date = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                    )

        db.session.commit()

        return redirect(url_for('main'))

    else:
        if len(get_id)>0:
            
            task = Tasks.query.get(get_id)
            oldtasks = OldTasks.query.filter_by(tid=get_id).order_by("uid desc").all()
            task.uid = hashids.encrypt(int(task.uid))
            if task is not None:
                return render_template('edit.html', task=task, commons=commons, oldtasks=oldtasks)
            else:
                return redirect(url_for('main'))
        else:
            return redirect(url_for('page_not_found'))



@rms.route('/delete_task', methods=['POST'])
@login_required
def delete_task():
    if request.method == 'POST':
        uid = request.form['taskid']
        uid = hashids.decrypt(uid)
        task = Tasks.query.filter_by(uid=uid).first()
        if scheduler.get_job(str(task.uid)):
            scheduler.remove_job(task.uid)
        db.session.delete(task)
        db.session.query(OldTasks).filter(OldTasks.tid == task.uid).delete()
        db.session.commit()
        log.info(str(task.uid)+" deleted")
        return 'True'
    else:
        print 'wrong methods'
        return 'False'



@rms.route('/api/runtask/by-name/<jobname>', methods=['POST','GET'])
def api(jobname=''):
    if request.method == 'GET':
        jobname = urldecode(jobname)
        log.info(jobname+" Called by API") 
        if current_user.is_authenticated:
            if not 'api' in current_user.roles:
                return jsonify({'error':'you\'re not allowed to work with api'})
	    
            repl = Tasks.query.filter_by(jobname = jobname).first()
            if repl:
                scheduler.add_job(
                          runner,
                          kwargs = {'uid':repl.uid},
                          run_date = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                          )
                return jsonify(task={'running':jobname})
            else:
                return jsonify({'error':'task not found'})
        else:
            return jsonify({'error':'not logged in'})
    else:
        return jsonify({'error':'Invalid HTTP method. Please use GET'})
        




















