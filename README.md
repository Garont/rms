remote task scheduler
=====================

Remote task scheduler/executor written on python using gevent, flask, apscheduler and paramiko

![Main Window](http://i.imgur.com/CPleRWl.png)

installation:

clone project

create python venv

activate python venv

> `./installation.bash`

create db and fill config.py

> `python run.py`

DON'T FORGET TO HIDE IT BEHIND THE FIREWALL. NO PENTEST WAS EVER MADE ON THIS SOFTWARE!

api call example:
```
curl -u apiuser:apipass http://rms.example.com:12000/api/runtask/by-name/task%20for%20QA
{
 "task": {
   "running": "task for QA"
 }
}
```












LICENCE INFO
============

MIT License

Copyright (c) 2016 Roman Shkurov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
