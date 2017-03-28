#!/usr/bin/env python
from rms import rms
from gevent.wsgi import WSGIServer

if __name__ == '__main__':
    http_server = WSGIServer(('', 12000), rms)
    http_server.serve_forever()

