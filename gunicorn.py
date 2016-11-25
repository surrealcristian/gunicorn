import argparse
import base64
import binascii
import cgi
import email.utils
import errno
import fcntl
import io
import logging
import os
import pwd
import random
import re
import resource
import select
import signal
import socket
import stat
import sys
import tempfile
import threading
import textwrap
import time
import traceback

from datetime import datetime
from errno import ENOTCONN
from logging.config import fileConfig
from os import closerange, sendfile
from random import randint
from urllib.parse import unquote_to_bytes, urlsplit


__version__ = '19.6.0'
SERVER_SOFTWARE = "gunicorn/%s" % __version__


##########
# Config
##########

def pre_request_fn(worker, req):
    worker.log.debug("%s %s" % (req.method, req.path))


class Config:
    def __init__(self):
        # settings

        """
        The Gunicorn config file.

        A string of the form ``PATH``, ``file:PATH``, or
        ``python:MODULE_NAME``.

        Only has an effect when specified on the command line or as part of an
        application specific configuration.
        """
        self.config = None

        """
        The unix sockets to bind.
        """
        self.bind = ['/tmp/gunicorn.socket']

        """
        The maximum number of pending connections.

        This refers to the number of clients that can be waiting to be served.
        Exceeding this number results in the client getting an error when
        attempting to connect. It should only affect servers under significant
        load.

        Must be a positive integer. Generally set in the 64-2048 range.
        """
        self.backlog = 2048

        """
        The number of worker processes for handling requests.

        A positive integer generally in the ``2-4 x $(NUM_CORES)`` range.
        You'll want to vary this a bit to find the best for your particular
        application's work load.

        By default, the value of the ``WEB_CONCURRENCY`` environment variable.
        If it is not defined, the default is ``1``.
        """
        self.workers = 4

        """
        The maximum number of requests a worker will process before restarting.

        Any value greater than zero will limit the number of requests a work
        will process before automatically restarting. This is a simple method
        to help limit the damage of memory leaks.

        If this is set to zero (the default) then the automatic worker
        restarts are disabled.
        """
        self.max_requests = 0

        """
        The maximum jitter to add to the *max_requests* setting.

        The jitter causes the restart per worker to be randomized by
        ``randint(0, max_requests_jitter)``. This is intended to stagger worker
        restarts to avoid all workers restarting at the same time.
        """
        self.max_requests_jitter = 0

        """
        Workers silent for more than this many seconds are killed and
        restarted.

        Generally set to thirty seconds. Only set this noticeably higher if
        you're sure of the repercussions for sync workers. For the non sync
        workers it just means that the worker process is still communicating
        and is not tied to the length of time required to handle a single
        request.
        """
        self.timeout = 30

        """
        Timeout for graceful workers restart.

        After receiving a restart signal, workers have this much time to finish
        serving requests. Workers still alive after the timeout (starting from
        the receipt of the restart signal) are force killed.
        """
        self.graceful_timeout = 30

        """
        The number of seconds to wait for requests on a Keep-Alive connection.

        Generally set in the 1-5 seconds range.
        """
        self.keepalive = 2

        """
        Check the configuration.
        """
        self.check_config = False

        """
        Chdir to specified directory before apps loading.
        """
        self.chdir = getcwd()

        """
        Daemonize the Gunicorn process.

        Detaches the server from the controlling terminal and enters the
        background.
        """
        self.daemon = False

        """
        Set environment variable (key=value).

        Pass variables to the execution environment. Ex.::

            $ gunicorn -b 127.0.0.1:8000 --env FOO=1 test:app

        and test for the foo variable environment in your application.
        """
        self.raw_env = []

        """
        A filename to use for the PID file.

        If not set, no PID file will be written.
        """
        self.pidfile = None

        """
        Switch worker processes to run as this user.

        A valid user id (as an integer) or the name of a user that can be
        retrieved with a call to ``pwd.getpwnam(value)`` or ``None`` to not
        change the worker process user.
        """
        self.user = os.geteuid()

        """
        Switch worker process to run as this group.

        A valid group id (as an integer) or the name of a user that can be
        retrieved with a call to ``pwd.getgrnam(value)`` or ``None`` to not
        change the worker processes group.
        """
        self.group = os.getegid()

        """
        A bit mask for the file mode on files written by Gunicorn.

        Note that this affects unix socket permissions.

        A valid value for the ``os.umask(mode)`` call or a string compatible
        with ``int(value, 0)`` (``0`` means Python guesses the base, so values
        like ``0``, ``0xFF``, ``0022`` are valid for decimal, hex, and octal
        representations)
        """
        self.umask = 0

        """
        If true, set the worker process's group access list with all of the
        groups of which the specified username is a member, plus the specified
        group id.
        """
        self.initgroups = False

        """
        A dictionary containing headers and values that the front-end proxy
        uses to indicate HTTPS requests. These tell Gunicorn to set
        ``wsgi.url_scheme`` to ``https``, so your application can tell that the
        request is secure.

        The dictionary should map upper-case header names to exact string
        values. The value comparisons are case-sensitive, unlike the header
        names, so make sure they're exactly what your front-end proxy sends
        when handling HTTPS requests.

        It is important that your front-end proxy configuration ensures that
        the headers defined here can not be passed directly from the client.
        """
        self.secure_scheme_headers = {
            "X-FORWARDED-PROTOCOL": "ssl",
            "X-FORWARDED-PROTO": "https",
            "X-FORWARDED-SSL": "on"
        }

        """
        Front-end's IPs from which allowed to handle set secure headers.
        (comma separate).

        Set to ``*`` to disable checking of Front-end IPs (useful for setups
        where you don't know in advance the IP address of Front-end, but
        you still trust the environment).

        By default, the value of the ``FORWARDED_ALLOW_IPS`` environment
        variable. If it is not defined, the default is ``"127.0.0.1"``.
        """
        self.forwarded_allow_ips = ['127.0.0.1']

        """
        The Access log file to write to.

        ``'-'`` means log to stdout.
        """
        self.accesslog = None

        """
        The access log format.

        ===========  ===========
        Identifier   Description
        ===========  ===========
        h            remote address
        l            ``'-'``
        u            user name
        t            date of the request
        r            status line (e.g. ``GET / HTTP/1.1``)
        m            request method
        U            URL path without query string
        q            query string
        H            protocol
        s            status
        B            response length
        b            response length or ``'-'`` (CLF format)
        f            referer
        a            user agent
        T            request time in seconds
        D            request time in microseconds
        L            request time in decimal seconds
        p            process ID
        {Header}i    request header
        {Header}o    response header
        {Variable}e  environment variable
        ===========  ===========
        """
        self.access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"',  # noqa

        """
        The Error log file to write to.

        Using ``'-'`` for FILE makes gunicorn log to stderr.

        .. versionchanged:: 19.2
            Log to stderr by default.

        """
        self.errorlog = '-'

        """
        The granularity of Error log outputs.

        Valid level names are:

        * debug
        * info
        * warning
        * error
        * critical
        """
        self.loglevel = 'debug'

        """
        The log config file to use.
        Gunicorn uses the standard Python logging module's Configuration
        file format.
        """
        self.logconfig = None

        """
        Enable stdio inheritance.

        Enable inheritance for stdio file descriptors in daemon mode.

        Note: To disable the Python stdout buffering, you can to set the user
        environment variable ``PYTHONUNBUFFERED`` .
        """
        self.enable_stdio_inheritance = False

        """
        A base to use with setproctitle for process naming.

        This affects things like ``ps`` and ``top``. If you're going to be
        running more than one instance of Gunicorn you'll probably want to set
        a name to tell them apart. This requires that you install the
        setproctitle module.

        If not set, the *default_proc_name* setting will be used.
        """
        self.proc_name_internal = None

        """
        Internal setting that is adjusted for each type of application.
        """
        self.default_proc_name = 'gunicorn'

        """
        A comma-separated list of directories to add to the Python path.

        e.g.
        ``'/home/djangoprojects/myproject,/home/python/mylibrary'``.
        """
        self.pythonpath = None

        """
        Enable detect PROXY protocol (PROXY mode).

        Allow using HTTP and Proxy together. It may be useful for work with
        stunnel as HTTPS frontend and Gunicorn as HTTP server.

        PROXY protocol:
        http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt

        Example for stunnel config::

            [https]
            protocol = proxy
            accept  = 443
            connect = 80
            cert = /etc/ssl/certs/stunnel.pem
            key = /etc/ssl/certs/stunnel.key
        """
        self.proxy_protocol = False

        """
        Front-end's IPs from which allowed accept proxy requests (comma
        separate).

        Set to ``*`` to disable checking of Front-end IPs (useful for setups
        where you don't know in advance the IP address of Front-end, but
        you still trust the environment)
        """
        self.proxy_allow_ips = ['127.0.0.1']

        # hooks

        """
        Called just before the master process is initialized.

        The callable needs to accept a single instance variable for the
        Arbiter.
        """
        self.on_starting = None

        """
        Called to recycle workers during a reload via SIGHUP.

        The callable needs to accept a single instance variable for the
        Arbiter.
        """
        self.on_reload = None

        """
        Called just after the server is started.

        The callable needs to accept a single instance variable for the
        Arbiter.
        """
        self.when_ready = None

        """
        Called just before a worker is forked.

        The callable needs to accept two instance variables for the Arbiter and
        new Worker.
        """
        self.pre_fork = None

        """
        Called just after a worker has been forked.

        The callable needs to accept two instance variables for the Arbiter and
        new Worker.
        """
        self.post_fork = None

        """
        Called just after a worker has initialized the application.

        The callable needs to accept one instance variable for the initialized
        Worker.
        """
        self.post_worker_init = None

        """
        Called just after a worker exited on SIGINT or SIGQUIT.

        The callable needs to accept one instance variable for the initialized
        Worker.
        """
        self.worker_int = None

        """
        Called when a worker received the SIGABRT signal.

        This call generally happens on timeout.

        The callable needs to accept one instance variable for the initialized
        Worker.
        """
        self.worker_abort = None

        """
        Called just before a new master process is forked.

        The callable needs to accept a single instance variable for the
        Arbiter.
        """
        self.pre_exec = None

        """
        Called just before a worker processes the request.

        The callable needs to accept two instance variables for the Worker and
        the Request.
        """
        self.pre_request = pre_request_fn

        """
        Called after a worker processes the request.

        The callable needs to accept two instance variables for the Worker and
        the Request.
        """
        self.post_request = None

        """
        Called just after a worker has been exited.

        The callable needs to accept two instance variables for the Arbiter and
        the just-exited Worker.
        """
        self.worker_exit = None

        """
        Called just after *num_workers* has been changed.

        The callable needs to accept an instance variable of the Arbiter and
        two integers of number of workers after and before change.

        If the number of workers is set for the first time, *old_value* would
        be ``None``.
        """
        self.nworkers_changed = None

        """
        Called just before exiting Gunicorn.

        The callable needs to accept a single instance variable for the
        Arbiter.
        """
        self.on_exit = None

    @property
    def address(self):
        return self.bind

    @property
    def uid(self):
        return self.user

    @property
    def gid(self):
        return self.group

    @property
    def proc_name(self):
        pn = self.proc_name_internal
        if pn is not None:
            return pn
        else:
            return self.default_proc_name

    @property
    def env(self):
        raw_env = self.raw_env
        env = {}

        if not raw_env:
            return env

        for e in raw_env:
            s = bytes_to_str(e)
            try:
                k, v = s.split('=', 1)
            except ValueError:
                raise RuntimeError("environment setting %r invalid" % s)

            env[k] = v

        return env

    @property
    def sendfile(self):
        if 'SENDFILE' in os.environ:
            sendfile = os.environ['SENDFILE'].lower()
            return sendfile in ['y', '1', 'yes', 'true']

        return True


##########
# Errors
##########

# we inherit from BaseException here to make sure to not be caucght
# at application level
class HaltServer(BaseException):
    def __init__(self, reason, exit_status=1):
        self.reason = reason
        self.exit_status = exit_status

    def __str__(self):
        return "<HaltServer %r %d>" % (self.reason, self.exit_status)


class ConfigError(Exception):
    """ Exception raised on config error """


class AppImportError(Exception):
    """ Exception raised when loading an application """


########
# Util
########


MAXFD = 1024
REDIRECT_TO = getattr(os, 'devnull', '/dev/null')

timeout_default = object()

CHUNK_SIZE = (16 * 1024)

MAX_BODY = 1024 * 132

# Server and Date aren't technically hop-by-hop
# headers, but they are in the purview of the
# origin server which the WSGI spec says we should
# act like. So we drop them and add our own.
#
# In the future, concatenation server header values
# might be better, but nothing else does it and
# dropping them is easier.
hop_headers = set("""
    connection keep-alive proxy-authenticate proxy-authorization
    te trailers transfer-encoding upgrade
    server date
    """.split())

try:
    from setproctitle import setproctitle

    def _setproctitle(title):
        setproctitle("gunicorn: %s" % title)
except ImportError:
    def _setproctitle(title):
        return


def getcwd():
    # get current path, try to use PWD env first
    try:
        a = os.stat(os.environ['PWD'])
        b = os.stat(os.getcwd())
        if a.st_ino == b.st_ino and a.st_dev == b.st_dev:
            cwd = os.environ['PWD']
        else:
            cwd = os.getcwd()
    except:
        cwd = os.getcwd()
    return cwd


def get_username(uid):
    """ get the username for a user id"""
    return pwd.getpwuid(uid).pw_name


def set_owner_process(uid, gid, initgroups=False):
    """ set user and group of workers processes """

    if gid:
        if uid:
            try:
                username = get_username(uid)
            except KeyError:
                initgroups = False

        # versions of python < 2.6.2 don't manage unsigned int for
        # groups like on osx or fedora
        gid = abs(gid) & 0x7FFFFFFF

        if initgroups:
            os.initgroups(username, gid)
        else:
            os.setgid(gid)

    if uid:
        os.setuid(uid)


def chown(path, uid, gid):
    gid = abs(gid) & 0x7FFFFFFF  # see note above.
    os.chown(path, uid, gid)


_unlink = os.unlink


def unlink(filename):
    try:
        _unlink(filename)
    except OSError as error:
        # The filename need not exist.
        if error.errno not in (errno.ENOENT, errno.ENOTDIR):
            raise


def get_maxfd():
    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if (maxfd == resource.RLIM_INFINITY):
        maxfd = MAXFD
    return maxfd


def close_on_exec(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    flags |= fcntl.FD_CLOEXEC
    fcntl.fcntl(fd, fcntl.F_SETFD, flags)


def set_non_blocking(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)


def close(sock):
    try:
        sock.close()
    except socket.error:
        pass


def write_chunk(sock, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    chunk_size = "%X\r\n" % len(data)
    chunk = b"".join([chunk_size.encode('utf-8'), data, b"\r\n"])
    sock.sendall(chunk)


def write(sock, data, chunked=False):
    if chunked:
        return write_chunk(sock, data)
    sock.sendall(data)


def write_nonblock(sock, data, chunked=False):
    timeout = sock.gettimeout()
    if timeout != 0.0:
        try:
            sock.setblocking(0)
            return write(sock, data, chunked)
        finally:
            sock.setblocking(1)
    else:
        return write(sock, data, chunked)


def writelines(sock, lines, chunked=False):
    for line in list(lines):
        write(sock, line, chunked)


def write_error(sock, status_int, reason, mesg):
    html = textwrap.dedent("""\
    <html>
      <head>
        <title>%(reason)s</title>
      </head>
      <body>
        <h1><p>%(reason)s</p></h1>
        %(mesg)s
      </body>
    </html>
    """) % {"reason": reason, "mesg": cgi.escape(mesg)}

    http = textwrap.dedent("""\
    HTTP/1.1 %s %s\r
    Connection: close\r
    Content-Type: text/html\r
    Content-Length: %d\r
    \r
    %s""") % (str(status_int), reason, len(html), html)
    write_nonblock(sock, http.encode('latin1'))


def normalize_name(name):
    return "-".join([w.lower().capitalize() for w in name.split("-")])


def import_app(module):
    parts = module.split(":", 1)
    if len(parts) == 1:
        module, obj = module, "application"
    else:
        module, obj = parts[0], parts[1]

    try:
        __import__(module)
    except ImportError:
        if module.endswith(".py") and os.path.exists(module):
            msg = "Failed to find application, did you mean '%s:%s'?"
            raise ImportError(msg % (module.rsplit(".", 1)[0], obj))
        else:
            raise

    mod = sys.modules[module]

    is_debug = logging.root.level == logging.DEBUG
    try:
        app = eval(obj, mod.__dict__)
    except NameError:
        if is_debug:
            traceback.print_exception(*sys.exc_info())
        raise AppImportError("Failed to find application: %r" % module)

    if app is None:
        raise AppImportError("Failed to find application object: %r" % obj)

    if not callable(app):
        raise AppImportError("Application object must be callable.")
    return app


def http_date(timestamp=None):
    """Return the current date and time formatted for a message header."""
    if timestamp is None:
        timestamp = time.time()
    s = email.utils.formatdate(timestamp, localtime=False, usegmt=True)
    return s


def is_hoppish(header):
    return header.lower().strip() in hop_headers


def daemonize(enable_stdio_inheritance=False):
    """\
    Standard daemonization of a process.
    http://www.svbug.com/documentation/comp.unix.programmer-FAQ/faq_2.html#SEC16
    """
    if 'GUNICORN_FD' not in os.environ:
        if os.fork():
            os._exit(0)
        os.setsid()

        if os.fork():
            os._exit(0)

        os.umask(0o22)

        # In both the following any file descriptors above stdin
        # stdout and stderr are left untouched. The inheritence
        # option simply allows one to have output go to a file
        # specified by way of shell redirection when not wanting
        # to use --error-log option.

        if not enable_stdio_inheritance:
            # Remap all of stdin, stdout and stderr on to
            # /dev/null. The expectation is that users have
            # specified the --error-log option.

            closerange(0, 3)

            fd_null = os.open(REDIRECT_TO, os.O_RDWR)

            if fd_null != 0:
                os.dup2(fd_null, 0)

            os.dup2(fd_null, 1)
            os.dup2(fd_null, 2)

        else:
            fd_null = os.open(REDIRECT_TO, os.O_RDWR)

            # Always redirect stdin to /dev/null as we would
            # never expect to need to read interactive input.

            if fd_null != 0:
                os.close(0)
                os.dup2(fd_null, 0)

            # If stdout and stderr are still connected to
            # their original file descriptors we check to see
            # if they are associated with terminal devices.
            # When they are we map them to /dev/null so that
            # are still detached from any controlling terminal
            # properly. If not we preserve them as they are.
            #
            # If stdin and stdout were not hooked up to the
            # original file descriptors, then all bets are
            # off and all we can really do is leave them as
            # they were.
            #
            # This will allow 'gunicorn ... > output.log 2>&1'
            # to work with stdout/stderr going to the file
            # as expected.
            #
            # Note that if using --error-log option, the log
            # file specified through shell redirection will
            # only be used up until the log file specified
            # by the option takes over. As it replaces stdout
            # and stderr at the file descriptor level, then
            # anything using stdout or stderr, including having
            # cached a reference to them, will still work.

            def redirect(stream, fd_expect):
                try:
                    fd = stream.fileno()
                    if fd == fd_expect and stream.isatty():
                        os.close(fd)
                        os.dup2(fd_null, fd)
                except AttributeError:
                    pass

            redirect(sys.stdout, 1)
            redirect(sys.stderr, 2)


def seed():
    try:
        random.seed(os.urandom(64))
    except NotImplementedError:
        random.seed('%s.%s' % (time.time(), os.getpid()))


def check_is_writeable(path):
    try:
        f = open(path, 'a')
    except IOError as e:
        raise RuntimeError("Error: '%s' isn't writable [%r]" % (path, e))
    f.close()


def to_bytestring(value, encoding="utf8"):
    """Converts a string argument to a byte string"""
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise TypeError('%r is not a string' % value)

    return value.encode(encoding)


def has_fileno(obj):
    if not hasattr(obj, "fileno"):
        return False

    # check BytesIO case and maybe others
    try:
        obj.fileno()
    except (AttributeError, IOError, io.UnsupportedOperation):
        return False

    return True


def warn(msg):
    print("!!!", file=sys.stderr)

    lines = msg.splitlines()
    for i, line in enumerate(lines):
        if i == 0:
            line = "WARNING: %s" % line
        print("!!! %s" % line, file=sys.stderr)

    print("!!!\n", file=sys.stderr)
    sys.stderr.flush()


def make_fail_app(msg):

    def app(environ, start_response):
        start_response("500 Internal Server Error", [
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(msg)))
        ])
        return [msg]

    return app


# functions from six.py

def reraise(tp, value, tb=None):
    """Reraise an exception."""
    if value is None:
        value = tp()
    if value.__traceback__ is not tb:
        raise value.with_traceback(tb)
    raise value


def with_metaclass(meta, *bases):
    """Create a base class with a metaclass."""
    # This requires a bit of explanation: the basic idea is to make a dummy
    # metaclass for one level of class instantiation that replaces itself with
    # the actual metaclass.
    class metaclass(meta):
        def __new__(cls, name, this_bases, d):
            return meta(name, bases, d)
    return type.__new__(metaclass, 'temporary_class', (), {})


def bytes_to_str(b):
    if isinstance(b, str):
        return b
    return str(b, 'latin1')


def unquote_to_wsgi_str(string):
    return unquote_to_bytes(string).decode('latin-1')


# The following code adapted from trollius.py33_exceptions
def _wrap_error(exc, mapping, key):
    if key not in mapping:
        return
    new_err_cls = mapping[key]
    new_err = new_err_cls(*exc.args)

    # raise a new exception with the original traceback
    reraise(
        new_err_cls, new_err,
        exc.__traceback__ if hasattr(exc, '__traceback__')
        else sys.exc_info()[2]
    )


class BlockingIOError(OSError):
    pass


class BrokenPipeError(OSError):
    pass


class ChildProcessError(OSError):
    pass


class ConnectionRefusedError(OSError):
    pass


class InterruptedError(OSError):
    pass


class ConnectionResetError(OSError):
    pass


class ConnectionAbortedError(OSError):
    pass


class PermissionError(OSError):
    pass


class FileNotFoundError(OSError):
    pass


class ProcessLookupError(OSError):
    pass


_MAP_ERRNO = {
    errno.EACCES: PermissionError,
    errno.EAGAIN: BlockingIOError,
    errno.EALREADY: BlockingIOError,
    errno.ECHILD: ChildProcessError,
    errno.ECONNABORTED: ConnectionAbortedError,
    errno.ECONNREFUSED: ConnectionRefusedError,
    errno.ECONNRESET: ConnectionResetError,
    errno.EINPROGRESS: BlockingIOError,
    errno.EINTR: InterruptedError,
    errno.ENOENT: FileNotFoundError,
    errno.EPERM: PermissionError,
    errno.EPIPE: BrokenPipeError,
    errno.ESHUTDOWN: BrokenPipeError,
    errno.EWOULDBLOCK: BlockingIOError,
    errno.ESRCH: ProcessLookupError,
}


def wrap_error(func, *args, **kw):
    """
    Wrap socket.error, IOError, OSError, select.error to raise new specialized
    exceptions of Python 3.3 like InterruptedError (PEP 3151).
    """
    try:
        return func(*args, **kw)
    except (socket.error, IOError, OSError) as exc:
        _wrap_error(exc, _MAP_ERRNO, exc.errno)
        raise
    except select.error as exc:
        if exc.args:
            _wrap_error(exc, _MAP_ERRNO, exc.args[0])
        raise


########
# Sock
########

SD_LISTEN_FDS_START = 3


class BaseSocket:

    def __init__(self, address, conf, log, fd=None):
        self.log = log
        self.conf = conf

        self.cfg_addr = address
        if fd is None:
            sock = socket.socket(self.FAMILY, socket.SOCK_STREAM)
            bound = False
        else:
            sock = socket.fromfd(fd, self.FAMILY, socket.SOCK_STREAM)
            os.close(fd)
            bound = True

        self.sock = self.set_options(sock, bound=bound)

    def __str__(self, name):
        return "<socket %d>" % self.sock.fileno()

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def set_options(self, sock, bound=False):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, 'SO_REUSEPORT'):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        if not bound:
            self.bind(sock)
        sock.setblocking(0)

        # make sure that the socket can be inherited
        if hasattr(sock, "set_inheritable"):
            sock.set_inheritable(True)

        sock.listen(self.conf.backlog)
        return sock

    def bind(self, sock):
        sock.bind(self.cfg_addr)

    def close(self):
        if self.sock is None:
            return

        try:
            self.sock.close()
        except socket.error as e:
            self.log.info("Error while closing socket %s", str(e))

        self.sock = None


class UnixSocket(BaseSocket):

    FAMILY = socket.AF_UNIX

    def __init__(self, addr, conf, log, fd=None):
        if fd is None:
            try:
                st = os.stat(addr)
            except OSError as e:
                if e.args[0] != errno.ENOENT:
                    raise
            else:
                if stat.S_ISSOCK(st.st_mode):
                    os.remove(addr)
                else:
                    raise ValueError("%r is not a socket" % addr)
        super(UnixSocket, self).__init__(addr, conf, log, fd=fd)

    def __str__(self):
        return "unix:%s" % self.cfg_addr

    def bind(self, sock):
        old_umask = os.umask(self.conf.umask)
        sock.bind(self.cfg_addr)
        chown(self.cfg_addr, self.conf.uid, self.conf.gid)
        os.umask(old_umask)

    def close(self):
        os.unlink(self.cfg_addr)
        super(UnixSocket, self).close()


def _sock_type(addr):
    if isinstance(addr, str):
        return UnixSocket
    raise TypeError("Unable to create socket from: %r" % addr)


def create_sockets(conf, log):
    """
    Create a new socket for the given address. If the address is a string, a
    Unix socket is created. Otherwise a TypeError is raised.
    """

    # Systemd support, use the sockets managed by systemd and passed to
    # gunicorn.
    # http://www.freedesktop.org/software/systemd/man/systemd.socket.html
    listeners = []
    if (
        'LISTEN_PID' in os.environ and
        int(os.environ.get('LISTEN_PID')) == os.getpid()
    ):
        for i in range(int(os.environ.get('LISTEN_FDS', 0))):
            fd = i + SD_LISTEN_FDS_START
            try:
                sock = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)
                sockname = sock.getsockname()
                if isinstance(sockname, str) and sockname.startswith('/'):
                    listeners.append(UnixSocket(sockname, conf, log, fd=fd))
            except socket.error:
                pass
        del os.environ['LISTEN_PID'], os.environ['LISTEN_FDS']

        if listeners:
            log.debug(
                'Socket activation sockets: %s',
                ",".join([str(l) for l in listeners])
            )
            return listeners

    # get it only once
    laddr = conf.address

    # sockets are already bound
    if 'GUNICORN_FD' in os.environ:
        fds = os.environ.pop('GUNICORN_FD').split(',')
        for i, fd in enumerate(fds):
            fd = int(fd)
            addr = laddr[i]
            sock_type = _sock_type(addr)

            try:
                listeners.append(sock_type(addr, conf, log, fd=fd))
            except socket.error as e:
                if e.args[0] == errno.ENOTCONN:
                    log.error("GUNICORN_FD should refer to an open socket.")
                else:
                    raise
        return listeners

    # no sockets is bound, first initialization of gunicorn in this env.
    for addr in laddr:
        sock_type = _sock_type(addr)
        # If we fail to create a socket from GUNICORN_FD
        # we fall through and try and open the socket
        # normally.
        sock = None
        for i in range(5):
            try:
                sock = sock_type(addr, conf, log)
            except socket.error as e:
                if e.args[0] == errno.EADDRINUSE:
                    log.error("Connection in use: %s", str(addr))
                if e.args[0] == errno.EADDRNOTAVAIL:
                    log.error("Invalid address: %s", str(addr))
                if i < 5:
                    msg = "connection to {addr} failed: {error}"
                    log.debug(msg.format(addr=str(addr), error=str(e)))
                    log.error("Retrying in 1 second.")
                    time.sleep(1)
            else:
                break

        if sock is None:
            log.error("Can't connect to %s", str(addr))
            sys.exit(1)

        listeners.append(sock)

    return listeners


###########
# Pidfile
###########

class Pidfile:
    """\
    Manage a PID file. If a specific name is provided
    it and '"%s.oldpid" % name' will be used. Otherwise
    we create a temp file using os.mkstemp.
    """

    def __init__(self, fname):
        self.fname = fname
        self.pid = None

    def create(self, pid):
        oldpid = self.validate()
        if oldpid:
            if oldpid == os.getpid():
                return
            msg = "Already running on PID %s (or pid file '%s' is stale)"
            raise RuntimeError(msg % (oldpid, self.fname))

        self.pid = pid

        # Write pidfile
        fdir = os.path.dirname(self.fname)
        if fdir and not os.path.isdir(fdir):
            raise RuntimeError(
                "%s doesn't exist. Can't create pidfile." % fdir
            )
        fd, fname = tempfile.mkstemp(dir=fdir)
        os.write(fd, ("%s\n" % self.pid).encode('utf-8'))
        if self.fname:
            os.rename(fname, self.fname)
        else:
            self.fname = fname
        os.close(fd)

        # set permissions to -rw-r--r--
        os.chmod(self.fname, 420)

    def rename(self, path):
        self.unlink()
        self.fname = path
        self.create(self.pid)

    def unlink(self):
        """ delete pidfile"""
        try:
            with open(self.fname, "r") as f:
                pid1 = int(f.read() or 0)

            if pid1 == self.pid:
                os.unlink(self.fname)
        except:
            pass

    def validate(self):
        """ Validate pidfile and make it stale if needed"""
        if not self.fname:
            return
        try:
            with open(self.fname, "r") as f:
                try:
                    wpid = int(f.read())
                except ValueError:
                    return

                try:
                    os.kill(wpid, 0)
                    return wpid
                except OSError as e:
                    if e.args[0] == errno.ESRCH:
                        return
                    raise
        except IOError as e:
            if e.args[0] == errno.ENOENT:
                return
            raise


##########
# Logger
##########

LOGGER_CONFIG_DEFAULTS = dict(
        version=1,
        disable_existing_loggers=False,

        loggers={
            "root": {"level": "INFO", "handlers": ["console"]},
            "gunicorn.error": {
                "level": "INFO",
                "handlers": ["error_console"],
                "propagate": True,
                "qualname": "gunicorn.error"
            },

            "gunicorn.access": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": True,
                "qualname": "gunicorn.access"
            }
        },
        handlers={
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "generic",
                "stream": "sys.stdout"
            },
            "error_console": {
                "class": "logging.StreamHandler",
                "formatter": "generic",
                "stream": "sys.stderr"
            },
        },
        formatters={
            "generic": {
                "format": "%(asctime)s [%(process)d] [%(levelname)s] %(message)s",  # noqa
                "datefmt": "[%Y-%m-%d %H:%M:%S %z]",
                "class": "logging.Formatter"
            }
        }
)


def loggers():
    """ get list of all loggers """
    root = logging.root
    existing = root.manager.loggerDict.keys()
    return [logging.getLogger(name) for name in existing]


class SafeAtoms(dict):

    def __init__(self, atoms):
        dict.__init__(self)
        for key, value in atoms.items():
            if isinstance(value, str):
                self[key] = value.replace('"', '\\"')
            else:
                self[key] = value

    def __getitem__(self, k):
        if k.startswith("{"):
            kl = k.lower()
            if kl in self:
                return super(SafeAtoms, self).__getitem__(kl)
            else:
                return "-"
        if k in self:
            return super(SafeAtoms, self).__getitem__(k)
        else:
            return '-'


class Logger:

    LOG_LEVELS = {
        "critical": logging.CRITICAL,
        "error": logging.ERROR,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.DEBUG
    }
    loglevel = logging.INFO

    error_fmt = r"%(asctime)s [%(process)d] [%(levelname)s] %(message)s"
    datefmt = r"[%Y-%m-%d %H:%M:%S %z]"

    access_fmt = "%(message)s"

    atoms_wrapper_class = SafeAtoms

    def __init__(self, cfg):
        self.error_log = logging.getLogger("gunicorn.error")
        self.error_log.propagate = False
        self.access_log = logging.getLogger("gunicorn.access")
        self.access_log.propagate = False
        self.error_handlers = []
        self.access_handlers = []
        self.logfile = None
        self.lock = threading.Lock()
        self.cfg = cfg
        self.setup(cfg)

    def setup(self, cfg):
        self.loglevel = self.LOG_LEVELS.get(cfg.loglevel.lower(), logging.INFO)
        self.error_log.setLevel(self.loglevel)
        self.access_log.setLevel(logging.INFO)

        self._set_handler(self.error_log, cfg.errorlog,
                          logging.Formatter(self.error_fmt, self.datefmt))

        # set gunicorn.access handler
        if cfg.accesslog is not None:
            self._set_handler(
                self.access_log, cfg.accesslog,
                fmt=logging.Formatter(self.access_fmt), stream=sys.stdout
            )

        if cfg.logconfig:
            if os.path.exists(cfg.logconfig):
                defaults = LOGGER_CONFIG_DEFAULTS.copy()
                defaults['__file__'] = cfg.logconfig
                defaults['here'] = os.path.dirname(cfg.logconfig)
                fileConfig(cfg.logconfig, defaults=defaults,
                           disable_existing_loggers=False)
            else:
                msg = "Error: log config '%s' not found"
                raise RuntimeError(msg % cfg.logconfig)

    def critical(self, msg, *args, **kwargs):
        self.error_log.critical(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.error_log.error(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.error_log.warning(msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self.error_log.info(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self.error_log.debug(msg, *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        self.error_log.exception(msg, *args, **kwargs)

    def log(self, lvl, msg, *args, **kwargs):
        if isinstance(lvl, str):
            lvl = self.LOG_LEVELS.get(lvl.lower(), logging.INFO)
        self.error_log.log(lvl, msg, *args, **kwargs)

    def atoms(self, resp, req, environ, request_time):
        """ Gets atoms for log formating.
        """
        status = resp.status
        if isinstance(status, str):
            status = status.split(None, 1)[0]
        atoms = {
            'h': environ.get('REMOTE_ADDR', '-'),
            'l': '-',
            'u': self._get_user(environ) or '-',
            't': self.now(),
            'r': "%s %s %s" % (
                environ['REQUEST_METHOD'], environ['RAW_URI'],
                environ["SERVER_PROTOCOL"]
            ),
            's': status,
            'm': environ.get('REQUEST_METHOD'),
            'U': environ.get('PATH_INFO'),
            'q': environ.get('QUERY_STRING'),
            'H': environ.get('SERVER_PROTOCOL'),
            'b': getattr(resp, 'sent', None) and str(resp.sent) or '-',
            'B': getattr(resp, 'sent', None),
            'f': environ.get('HTTP_REFERER', '-'),
            'a': environ.get('HTTP_USER_AGENT', '-'),
            'T': request_time.seconds,
            'D': (request_time.seconds*1000000) + request_time.microseconds,
            'L': "%d.%06d" % (request_time.seconds, request_time.microseconds),
            'p': "<%s>" % os.getpid()
        }

        # add request headers
        if hasattr(req, 'headers'):
            req_headers = req.headers
        else:
            req_headers = req

        if hasattr(req_headers, "items"):
            req_headers = req_headers.items()

        atoms.update(dict([("{%s}i" % k.lower(), v) for k, v in req_headers]))

        resp_headers = resp.headers
        if hasattr(resp_headers, "items"):
            resp_headers = resp_headers.items()

        # add response headers
        atoms.update(dict([("{%s}o" % k.lower(), v) for k, v in resp_headers]))

        # add environ variables
        environ_variables = environ.items()
        atoms.update(
            dict([("{%s}e" % k.lower(), v) for k, v in environ_variables])
        )

        return atoms

    def access(self, resp, req, environ, request_time):
        """ See http://httpd.apache.org/docs/2.0/logs.html#combined
        for format details
        """

        if not (self.cfg.accesslog or self.cfg.logconfig):
            return

        # wrap atoms:
        # - make sure atoms will be test case insensitively
        # - if atom doesn't exist replace it by '-'
        safe_atoms = self.atoms_wrapper_class(
            self.atoms(resp, req, environ, request_time)
        )

        try:
            self.access_log.info(self.cfg.access_log_format % safe_atoms)
        except:
            self.error(traceback.format_exc())

    def now(self):
        """ return date in Apache Common Log Format """
        return time.strftime('[%d/%b/%Y:%H:%M:%S %z]')

    def reopen_files(self):
        for log in loggers():
            for handler in log.handlers:
                if isinstance(handler, logging.FileHandler):
                    handler.acquire()
                    try:
                        if handler.stream:
                            handler.stream.close()
                            handler.stream = open(handler.baseFilename,
                                                  handler.mode)
                    finally:
                        handler.release()

    def close_on_exec(self):
        for log in loggers():
            for handler in log.handlers:
                if isinstance(handler, logging.FileHandler):
                    handler.acquire()
                    try:
                        if handler.stream:
                            close_on_exec(handler.stream.fileno())
                    finally:
                        handler.release()

    def _get_gunicorn_handler(self, log):
        for h in log.handlers:
            if getattr(h, "_gunicorn", False):
                return h

    def _set_handler(self, log, output, fmt, stream=None):
        # remove previous gunicorn log handler
        h = self._get_gunicorn_handler(log)
        if h:
            log.handlers.remove(h)

        if output is not None:
            if output == "-":
                h = logging.StreamHandler(stream)
            else:
                check_is_writeable(output)
                h = logging.FileHandler(output)
                # make sure the user can reopen the file
                try:
                    os.chown(h.baseFilename, self.cfg.user, self.cfg.group)
                except OSError:
                    # it's probably OK there, we assume the user has given
                    # /dev/null as a parameter.
                    pass

            h.setFormatter(fmt)
            h._gunicorn = True
            log.addHandler(h)

    def _get_user(self, environ):
        user = None
        http_auth = environ.get("HTTP_AUTHORIZATION")
        if http_auth and http_auth.startswith('Basic'):
            auth = http_auth.split(" ", 1)
            if len(auth) == 2:
                try:
                    # b64decode doesn't accept unicode in Python < 3.3
                    # so we need to convert it to a byte string
                    auth = base64.b64decode(auth[1].strip().encode('utf-8'))
                    auth = auth.decode('utf-8')
                    auth = auth.split(":", 1)
                except TypeError as exc:
                    self.debug("Couldn't get username: %s", exc)
                    return user
                except binascii.Error as exc:
                    self.debug("Couldn't get username: %s", exc)
                    return user
                if len(auth) == 2:
                    user = auth[0]
        return user


########
# HTTP
########

class ParseException(Exception):
    pass


class NoMoreData(IOError):
    def __init__(self, buf=None):
        self.buf = buf

    def __str__(self):
        return "No more data after: %r" % self.buf


class InvalidRequestLine(ParseException):
    def __init__(self, req):
        self.req = req
        self.code = 400

    def __str__(self):
        return "Invalid HTTP request line: %r" % self.req


class InvalidRequestMethod(ParseException):
    def __init__(self, method):
        self.method = method

    def __str__(self):
        return "Invalid HTTP method: %r" % self.method


class InvalidHTTPVersion(ParseException):
    def __init__(self, version):
        self.version = version

    def __str__(self):
        return "Invalid HTTP Version: %r" % self.version


class InvalidHeader(ParseException):
    def __init__(self, hdr, req=None):
        self.hdr = hdr
        self.req = req

    def __str__(self):
        return "Invalid HTTP Header: %r" % self.hdr


class InvalidHeaderName(ParseException):
    def __init__(self, hdr):
        self.hdr = hdr

    def __str__(self):
        return "Invalid HTTP header name: %r" % self.hdr


class InvalidChunkSize(IOError):
    def __init__(self, data):
        self.data = data

    def __str__(self):
        return "Invalid chunk size: %r" % self.data


class ChunkMissingTerminator(IOError):
    def __init__(self, term):
        self.term = term

    def __str__(self):
        return "Invalid chunk terminator is not '\\r\\n': %r" % self.term


class InvalidProxyLine(ParseException):
    def __init__(self, line):
        self.line = line
        self.code = 400

    def __str__(self):
        return "Invalid PROXY line: %r" % self.line


class ForbiddenProxyRequest(ParseException):
    def __init__(self, host):
        self.host = host
        self.code = 403

    def __str__(self):
        return "Proxy request from %r not allowed" % self.host


class ChunkedReader:
    def __init__(self, req, unreader):
        self.req = req
        self.parser = self.parse_chunked(unreader)
        self.buf = io.BytesIO()

    def read(self, size):
        if not isinstance(size, int):
            raise TypeError("size must be an integral type")
        if size < 0:
            raise ValueError("Size must be positive.")
        if size == 0:
            return b""

        if self.parser:
            while self.buf.tell() < size:
                try:
                    self.buf.write(next(self.parser))
                except StopIteration:
                    self.parser = None
                    break

        data = self.buf.getvalue()
        ret, rest = data[:size], data[size:]
        self.buf = io.BytesIO()
        self.buf.write(rest)
        return ret

    def parse_trailers(self, unreader, data):
        buf = io.BytesIO()
        buf.write(data)

        idx = buf.getvalue().find(b"\r\n\r\n")
        done = buf.getvalue()[:2] == b"\r\n"
        while idx < 0 and not done:
            self.get_data(unreader, buf)
            idx = buf.getvalue().find(b"\r\n\r\n")
            done = buf.getvalue()[:2] == b"\r\n"
        if done:
            unreader.unread(buf.getvalue()[2:])
            return b""
        self.req.trailers = self.req.parse_headers(buf.getvalue()[:idx])
        unreader.unread(buf.getvalue()[idx + 4:])

    def parse_chunked(self, unreader):
        (size, rest) = self.parse_chunk_size(unreader)
        while size > 0:
            while size > len(rest):
                size -= len(rest)
                yield rest
                rest = unreader.read()
                if not rest:
                    raise NoMoreData()
            yield rest[:size]
            # Remove \r\n after chunk
            rest = rest[size:]
            while len(rest) < 2:
                rest += unreader.read()
            if rest[:2] != b'\r\n':
                raise ChunkMissingTerminator(rest[:2])
            (size, rest) = self.parse_chunk_size(unreader, data=rest[2:])

    def parse_chunk_size(self, unreader, data=None):
        buf = io.BytesIO()
        if data is not None:
            buf.write(data)

        idx = buf.getvalue().find(b"\r\n")
        while idx < 0:
            self.get_data(unreader, buf)
            idx = buf.getvalue().find(b"\r\n")

        data = buf.getvalue()
        line, rest_chunk = data[:idx], data[idx + 2:]

        chunk_size = line.split(b";", 1)[0].strip()
        try:
            chunk_size = int(chunk_size, 16)
        except ValueError:
            raise InvalidChunkSize(chunk_size)

        if chunk_size == 0:
            try:
                self.parse_trailers(unreader, rest_chunk)
            except NoMoreData:
                pass
            return (0, None)
        return (chunk_size, rest_chunk)

    def get_data(self, unreader, buf):
        data = unreader.read()
        if not data:
            raise NoMoreData()
        buf.write(data)


class LengthReader:
    def __init__(self, unreader, length):
        self.unreader = unreader
        self.length = length

    def read(self, size):
        if not isinstance(size, int):
            raise TypeError("size must be an integral type")

        size = min(self.length, size)
        if size < 0:
            raise ValueError("Size must be positive.")
        if size == 0:
            return b""

        buf = io.BytesIO()
        data = self.unreader.read()
        while data:
            buf.write(data)
            if buf.tell() >= size:
                break
            data = self.unreader.read()

        buf = buf.getvalue()
        ret, rest = buf[:size], buf[size:]
        self.unreader.unread(rest)
        self.length -= size
        return ret


class EOFReader:
    def __init__(self, unreader):
        self.unreader = unreader
        self.buf = io.BytesIO()
        self.finished = False

    def read(self, size):
        if not isinstance(size, int):
            raise TypeError("size must be an integral type")
        if size < 0:
            raise ValueError("Size must be positive.")
        if size == 0:
            return b""

        if self.finished:
            data = self.buf.getvalue()
            ret, rest = data[:size], data[size:]
            self.buf = io.BytesIO()
            self.buf.write(rest)
            return ret

        data = self.unreader.read()
        while data:
            self.buf.write(data)
            if self.buf.tell() > size:
                break
            data = self.unreader.read()

        if not data:
            self.finished = True

        data = self.buf.getvalue()
        ret, rest = data[:size], data[size:]
        self.buf = io.BytesIO()
        self.buf.write(rest)
        return ret


class Body:
    def __init__(self, reader):
        self.reader = reader
        self.buf = io.BytesIO()

    def __iter__(self):
        return self

    def __next__(self):
        ret = self.readline()
        if not ret:
            raise StopIteration()
        return ret
    next = __next__

    def getsize(self, size):
        if size is None:
            return sys.maxsize
        elif not isinstance(size, int):
            raise TypeError("size must be an integral type")
        elif size < 0:
            return sys.maxsize
        return size

    def read(self, size=None):
        size = self.getsize(size)
        if size == 0:
            return b""

        if size < self.buf.tell():
            data = self.buf.getvalue()
            ret, rest = data[:size], data[size:]
            self.buf = io.BytesIO()
            self.buf.write(rest)
            return ret

        while size > self.buf.tell():
            data = self.reader.read(1024)
            if not len(data):
                break
            self.buf.write(data)

        data = self.buf.getvalue()
        ret, rest = data[:size], data[size:]
        self.buf = io.BytesIO()
        self.buf.write(rest)
        return ret

    def readline(self, size=None):
        size = self.getsize(size)
        if size == 0:
            return b""

        data = self.buf.getvalue()
        self.buf = io.BytesIO()

        ret = []
        while 1:
            idx = data.find(b"\n", 0, size)
            idx = idx + 1 if idx >= 0 else size if len(data) >= size else 0
            if idx:
                ret.append(data[:idx])
                self.buf.write(data[idx:])
                break

            ret.append(data)
            size -= len(data)
            data = self.reader.read(min(1024, size))
            if not data:
                break

        return b"".join(ret)

    def readlines(self, size=None):
        ret = []
        data = self.read()
        while len(data):
            pos = data.find(b"\n")
            if pos < 0:
                ret.append(data)
                data = b""
            else:
                line, data = data[:pos + 1], data[pos + 1:]
                ret.append(line)
        return ret


class Unreader:
    def __init__(self):
        self.buf = io.BytesIO()

    def read(self, size=None):
        if size is not None and not isinstance(size, int):
            raise TypeError("size parameter must be an int or long.")

        if size is not None:
            if size == 0:
                return b""
            if size < 0:
                size = None

        self.buf.seek(0, os.SEEK_END)

        if size is None and self.buf.tell():
            ret = self.buf.getvalue()
            self.buf = io.BytesIO()
            return ret
        if size is None:
            d = self.chunk()
            return d

        while self.buf.tell() < size:
            chunk = self.chunk()
            if not len(chunk):
                ret = self.buf.getvalue()
                self.buf = io.BytesIO()
                return ret
            self.buf.write(chunk)
        data = self.buf.getvalue()
        self.buf = io.BytesIO()
        self.buf.write(data[size:])
        return data[:size]

    def unread(self, data):
        self.buf.seek(0, os.SEEK_END)
        self.buf.write(data)


class SocketUnreader(Unreader):
    def __init__(self, sock, max_chunk=8192):
        super(SocketUnreader, self).__init__()
        self.sock = sock
        self.mxchunk = max_chunk

    def chunk(self):
        return self.sock.recv(self.mxchunk)


class IterUnreader(Unreader):
    def __init__(self, iterable):
        super(IterUnreader, self).__init__()
        self.iter = iter(iterable)

    def chunk(self):
        if not self.iter:
            return b""
        try:
            return next(self.iter)
        except StopIteration:
            self.iter = None
            return b""


MAX_REQUEST_LINE = 8190
MAX_HEADERS = 32768
DEFAULT_MAX_HEADERFIELD_SIZE = 8190

HEADER_RE = re.compile("[\x00-\x1F\x7F()<>@,;:\[\]={} \t\\\\\"]")
METH_RE = re.compile(r"[A-Z0-9$-_.]{3,20}")
VERSION_RE = re.compile(r"HTTP/(\d+)\.(\d+)")


class Message:
    def __init__(self, cfg, unreader):
        self.cfg = cfg
        self.unreader = unreader
        self.version = None
        self.headers = []
        self.trailers = []
        self.body = None

        unused = self.parse(self.unreader)
        self.unreader.unread(unused)
        self.set_body_reader()

    def parse_headers(self, data):
        headers = []

        # Split lines on \r\n keeping the \r\n on each line
        lines = [bytes_to_str(line) + "\r\n" for line in data.split(b"\r\n")]

        # Parse headers into key/value pairs paying attention
        # to continuation lines.
        while len(lines):
            # Parse initial header name : value pair.
            curr = lines.pop(0)
            header_length = len(curr)
            if curr.find(":") < 0:
                raise InvalidHeader(curr.strip())
            name, value = curr.split(":", 1)
            name = name.rstrip(" \t").upper()
            if HEADER_RE.search(name):
                raise InvalidHeaderName(name)

            name, value = name.strip(), [value.lstrip()]

            # Consume value continuation lines
            while len(lines) and lines[0].startswith((" ", "\t")):
                curr = lines.pop(0)
                header_length += len(curr)
                value.append(curr)
            value = ''.join(value).rstrip()
            headers.append((name, value))
        return headers

    def set_body_reader(self):
        chunked = False
        content_length = None
        for (name, value) in self.headers:
            if name == "CONTENT-LENGTH":
                content_length = value
            elif name == "TRANSFER-ENCODING":
                chunked = value.lower() == "chunked"
            elif name == "SEC-WEBSOCKET-KEY1":
                content_length = 8

        if chunked:
            self.body = Body(ChunkedReader(self, self.unreader))
        elif content_length is not None:
            try:
                content_length = int(content_length)
            except ValueError:
                raise InvalidHeader("CONTENT-LENGTH", req=self)

            if content_length < 0:
                raise InvalidHeader("CONTENT-LENGTH", req=self)

            self.body = Body(LengthReader(self.unreader, content_length))
        else:
            self.body = Body(EOFReader(self.unreader))

    def should_close(self):
        for (h, v) in self.headers:
            if h == "CONNECTION":
                v = v.lower().strip()
                if v == "close":
                    return True
                elif v == "keep-alive":
                    return False
                break
        return self.version <= (1, 0)


class Request(Message):
    def __init__(self, cfg, unreader, req_number=1):
        self.method = None
        self.uri = None
        self.path = None
        self.query = None
        self.fragment = None

        self.req_number = req_number
        self.proxy_protocol_info = None
        super(Request, self).__init__(cfg, unreader)

    def get_data(self, unreader, buf, stop=False):
        data = unreader.read()
        if not data:
            if stop:
                raise StopIteration()
            raise NoMoreData(buf.getvalue())
        buf.write(data)

    def parse(self, unreader):
        buf = io.BytesIO()
        self.get_data(unreader, buf, stop=True)

        # get request line
        line, rbuf = self.read_line(unreader, buf)

        # proxy protocol
        if self.proxy_protocol(bytes_to_str(line)):
            # get next request line
            buf = io.BytesIO()
            buf.write(rbuf)
            line, rbuf = self.read_line(unreader, buf)

        self.parse_request_line(bytes_to_str(line))
        buf = io.BytesIO()
        buf.write(rbuf)

        # Headers
        data = buf.getvalue()
        idx = data.find(b"\r\n\r\n")

        done = data[:2] == b"\r\n"
        while True:
            idx = data.find(b"\r\n\r\n")
            done = data[:2] == b"\r\n"

            if idx < 0 and not done:
                self.get_data(unreader, buf)
                data = buf.getvalue()
            else:
                break

        if done:
            self.unreader.unread(data[2:])
            return b""

        self.headers = self.parse_headers(data[:idx])

        ret = data[idx + 4:]
        buf = io.BytesIO()
        return ret

    def read_line(self, unreader, buf):
        data = buf.getvalue()

        while True:
            idx = data.find(b"\r\n")
            if idx >= 0:
                # check if the request line is too large
                break
            self.get_data(unreader, buf)
            data = buf.getvalue()

        return (data[:idx],  # request line,
                data[idx + 2:])  # residue in the buffer, skip \r\n

    def proxy_protocol(self, line):
        """\
        Detect, check and parse proxy protocol.

        :raises: ForbiddenProxyRequest, InvalidProxyLine.
        :return: True for proxy protocol line else False
        """
        if not self.cfg.proxy_protocol:
            return False

        if self.req_number != 1:
            return False

        if not line.startswith("PROXY"):
            return False

        self.proxy_protocol_access_check()
        self.parse_proxy_protocol(line)

        return True

    def proxy_protocol_access_check(self):
        # check in allow list
        if isinstance(self.unreader, SocketUnreader):
            try:
                remote_host = self.unreader.sock.getpeername()[0]
            except socket.error as e:
                if e.args[0] == ENOTCONN:
                    raise ForbiddenProxyRequest("UNKNOW")
                raise
            if ("*" not in self.cfg.proxy_allow_ips and
                    remote_host not in self.cfg.proxy_allow_ips):
                raise ForbiddenProxyRequest(remote_host)

    def parse_proxy_protocol(self, line):
        bits = line.split()

        if len(bits) != 6:
            raise InvalidProxyLine(line)

        # Extract data
        proto = bits[1]
        s_addr = bits[2]
        d_addr = bits[3]

        # Validation
        if proto not in ["TCP4", "TCP6"]:
            raise InvalidProxyLine("protocol '%s' not supported" % proto)
        if proto == "TCP4":
            try:
                socket.inet_pton(socket.AF_INET, s_addr)
                socket.inet_pton(socket.AF_INET, d_addr)
            except socket.error:
                raise InvalidProxyLine(line)
        elif proto == "TCP6":
            try:
                socket.inet_pton(socket.AF_INET6, s_addr)
                socket.inet_pton(socket.AF_INET6, d_addr)
            except socket.error:
                raise InvalidProxyLine(line)

        try:
            s_port = int(bits[4])
            d_port = int(bits[5])
        except ValueError:
            raise InvalidProxyLine("invalid port %s" % line)

        if not ((0 <= s_port <= 65535) and (0 <= d_port <= 65535)):
            raise InvalidProxyLine("invalid port %s" % line)

        # Set data
        self.proxy_protocol_info = {
            "proxy_protocol": proto,
            "client_addr": s_addr,
            "client_port": s_port,
            "proxy_addr": d_addr,
            "proxy_port": d_port
        }

    def parse_request_line(self, line):
        bits = line.split(None, 2)
        if len(bits) != 3:
            raise InvalidRequestLine(line)

        # Method
        if not METH_RE.match(bits[0]):
            raise InvalidRequestMethod(bits[0])
        self.method = bits[0].upper()

        # URI
        # When the path starts with //, urlsplit considers it as a
        # relative uri while the RDF says it shouldnt
        # http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5.1.2
        # considers it as an absolute url.
        # fix issue #297
        if bits[1].startswith("//"):
            self.uri = bits[1][1:]
        else:
            self.uri = bits[1]

        try:
            parts = urlsplit(self.uri)
        except ValueError:
            raise InvalidRequestLine(line)
        self.path = parts.path or ""
        self.query = parts.query or ""
        self.fragment = parts.fragment or ""

        # Version
        match = VERSION_RE.match(bits[2])
        if match is None:
            raise InvalidHTTPVersion(bits[2])
        self.version = (int(match.group(1)), int(match.group(2)))

    def set_body_reader(self):
        super(Request, self).set_body_reader()
        if isinstance(self.body.reader, EOFReader):
            self.body = Body(LengthReader(self.unreader, 0))


class Parser:

    mesg_class = None

    def __init__(self, cfg, source):
        self.cfg = cfg
        if hasattr(source, "recv"):
            self.unreader = SocketUnreader(source)
        else:
            self.unreader = IterUnreader(source)
        self.mesg = None

        # request counter (for keepalive connetions)
        self.req_count = 0

    def __iter__(self):
        return self

    def __next__(self):
        # Stop if HTTP dictates a stop.
        if self.mesg and self.mesg.should_close():
            raise StopIteration()

        # Discard any unread body of the previous message
        if self.mesg:
            data = self.mesg.body.read(8192)
            while data:
                data = self.mesg.body.read(8192)

        # Parse the next request
        self.req_count += 1
        self.mesg = self.mesg_class(self.cfg, self.unreader, self.req_count)
        if not self.mesg:
            raise StopIteration()
        return self.mesg

    next = __next__


class RequestParser(Parser):

    mesg_class = Request


########
# WSGI
########

# Send files in at most 1GB blocks as some operating systems can have problems
# with sending files in blocks over 2GB.
BLKSIZE = 0x3FFFFFFF

NORMALIZE_SPACE = re.compile(r'(?:\r\n)?[ \t]+')
HEADER_VALUE_RE = re.compile(r'[\x00-\x1F\x7F]')

log = logging.getLogger(__name__)


class FileWrapper:

    def __init__(self, filelike, blksize=8192):
        self.filelike = filelike
        self.blksize = blksize
        if hasattr(filelike, 'close'):
            self.close = filelike.close

    def __getitem__(self, key):
        data = self.filelike.read(self.blksize)
        if data:
            return data
        raise IndexError


class WSGIErrorsWrapper(io.RawIOBase):

    def __init__(self, cfg):
        errorlog = logging.getLogger("gunicorn.error")
        handlers = errorlog.handlers
        self.streams = []

        if cfg.errorlog == "-":
            self.streams.append(sys.stderr)
            handlers = handlers[1:]

        for h in handlers:
            if hasattr(h, "stream"):
                self.streams.append(h.stream)

    def write(self, data):
        for stream in self.streams:
            try:
                stream.write(data)
            except UnicodeError:
                stream.write(data.encode("UTF-8"))
            stream.flush()


def base_environ(cfg):
    return {
        "wsgi.errors": WSGIErrorsWrapper(cfg),
        "wsgi.version": (1, 0),
        "wsgi.multithread": False,
        "wsgi.multiprocess": (cfg.workers > 1),
        "wsgi.run_once": False,
        "wsgi.file_wrapper": FileWrapper,
        "SERVER_SOFTWARE": SERVER_SOFTWARE,
    }


def default_environ(req, sock, cfg):
    env = base_environ(cfg)
    env.update({
        "wsgi.input": req.body,
        "gunicorn.socket": sock,
        "REQUEST_METHOD": req.method,
        "QUERY_STRING": req.query,
        "RAW_URI": req.uri,
        "SERVER_PROTOCOL": "HTTP/%s" % ".".join([str(v) for v in req.version])
    })
    return env


def proxy_environ(req):
    info = req.proxy_protocol_info

    if not info:
        return {}

    return {
        "PROXY_PROTOCOL": info["proxy_protocol"],
        "REMOTE_ADDR": info["client_addr"],
        "REMOTE_PORT": str(info["client_port"]),
        "PROXY_ADDR": info["proxy_addr"],
        "PROXY_PORT": str(info["proxy_port"]),
    }


def create(req, sock, client, server, cfg):
    resp = Response(req, sock, cfg)

    # set initial environ
    environ = default_environ(req, sock, cfg)

    # default variables
    host = None
    url_scheme = "http"
    script_name = os.environ.get("SCRIPT_NAME", "")

    # set secure_headers
    secure_headers = cfg.secure_scheme_headers
    if client and not isinstance(client, str):
        if (
            '*' not in cfg.forwarded_allow_ips and
            client[0] not in cfg.forwarded_allow_ips
        ):
            secure_headers = {}

    # add the headers to the environ
    for hdr_name, hdr_value in req.headers:
        if hdr_name == "EXPECT":
            # handle expect
            if hdr_value.lower() == "100-continue":
                sock.send(b"HTTP/1.1 100 Continue\r\n\r\n")
        elif secure_headers and (
            hdr_name in secure_headers and
            hdr_value == secure_headers[hdr_name]
        ):
            url_scheme = "https"
        elif hdr_name == 'HOST':
            host = hdr_value
        elif hdr_name == "SCRIPT_NAME":
            script_name = hdr_value
        elif hdr_name == "CONTENT-TYPE":
            environ['CONTENT_TYPE'] = hdr_value
            continue
        elif hdr_name == "CONTENT-LENGTH":
            environ['CONTENT_LENGTH'] = hdr_value
            continue

        key = 'HTTP_' + hdr_name.replace('-', '_')
        if key in environ:
            hdr_value = "%s,%s" % (environ[key], hdr_value)
        environ[key] = hdr_value

    # set the url scheme
    environ['wsgi.url_scheme'] = url_scheme

    # set the REMOTE_* keys in environ
    # authors should be aware that REMOTE_HOST and REMOTE_ADDR
    # may not qualify the remote addr:
    # http://www.ietf.org/rfc/rfc3875
    if isinstance(client, str):
        environ['REMOTE_ADDR'] = client
    elif isinstance(client, bytes):
        environ['REMOTE_ADDR'] = str(client)
    else:
        environ['REMOTE_ADDR'] = client[0]
        environ['REMOTE_PORT'] = str(client[1])

    # handle the SERVER_*
    # Normally only the application should use the Host header but since the
    # WSGI spec doesn't support unix sockets, we are using it to create
    # viable SERVER_* if possible.
    if isinstance(server, str):
        server = server.split(":")
        if len(server) == 1:
            # unix socket
            if host and host is not None:
                server = host.split(':')
                if len(server) == 1:
                    if url_scheme == "http":
                        server.append(80),
                    elif url_scheme == "https":
                        server.append(443)
                    else:
                        server.append('')
            else:
                # no host header given which means that we are not behind a
                # proxy, so append an empty port.
                server.append('')
    environ['SERVER_NAME'] = server[0]
    environ['SERVER_PORT'] = str(server[1])

    # set the path and script name
    path_info = req.path
    if script_name:
        path_info = path_info.split(script_name, 1)[1]
    environ['PATH_INFO'] = unquote_to_wsgi_str(path_info)
    environ['SCRIPT_NAME'] = script_name

    # override the environ with the correct remote and server address if
    # we are behind a proxy using the proxy protocol.
    environ.update(proxy_environ(req))
    return resp, environ


class Response:

    def __init__(self, req, sock, cfg):
        self.req = req
        self.sock = sock
        self.version = SERVER_SOFTWARE
        self.status = None
        self.chunked = False
        self.must_close = False
        self.headers = []
        self.headers_sent = False
        self.response_length = None
        self.sent = 0
        self.upgrade = False
        self.cfg = cfg

    def force_close(self):
        self.must_close = True

    def should_close(self):
        if self.must_close or self.req.should_close():
            return True
        if self.response_length is not None or self.chunked:
            return False
        if self.req.method == 'HEAD':
            return False
        if self.status_code < 200 or self.status_code in (204, 304):
            return False
        return True

    def start_response(self, status, headers, exc_info=None):
        if exc_info:
            try:
                if self.status and self.headers_sent:
                    reraise(exc_info[0], exc_info[1], exc_info[2])
            finally:
                exc_info = None
        elif self.status is not None:
            raise AssertionError("Response headers already set!")

        self.status = status

        # get the status code from the response here so we can use it to check
        # the need for the connection header later without parsing the string
        # each time.
        try:
            self.status_code = int(self.status.split()[0])
        except ValueError:
            self.status_code = None

        self.process_headers(headers)
        self.chunked = self.is_chunked()
        return self.write

    def process_headers(self, headers):
        for name, value in headers:
            if not isinstance(name, str):
                raise TypeError('%r is not a string' % name)

            if HEADER_RE.search(name):
                raise InvalidHeaderName('%r' % name)

            if HEADER_VALUE_RE.search(value):
                raise InvalidHeader('%r' % value)

            value = str(value).strip()
            lname = name.lower().strip()
            if lname == "content-length":
                self.response_length = int(value)
            elif is_hoppish(name):
                if lname == "connection":
                    # handle websocket
                    if value.lower().strip() == "upgrade":
                        self.upgrade = True
                elif lname == "upgrade":
                    if value.lower().strip() == "websocket":
                        self.headers.append((name.strip(), value))

                # ignore hopbyhop headers
                continue
            self.headers.append((name.strip(), value))

    def is_chunked(self):
        # Only use chunked responses when the client is
        # speaking HTTP/1.1 or newer and there was
        # no Content-Length header set.
        if self.response_length is not None:
            return False
        elif self.req.version <= (1, 0):
            return False
        elif self.req.method == 'HEAD':
            # Responses to a HEAD request MUST NOT contain a response body.
            return False
        elif self.status_code in (204, 304):
            # Do not use chunked responses when the response is guaranteed to
            # not have a response body.
            return False
        return True

    def default_headers(self):
        # set the connection header
        if self.upgrade:
            connection = "upgrade"
        elif self.should_close():
            connection = "close"
        else:
            connection = "keep-alive"

        headers = [
            "HTTP/%s.%s %s\r\n" % (self.req.version[0], self.req.version[1],
                                   self.status),
            "Server: %s\r\n" % self.version,
            "Date: %s\r\n" % http_date(),
            "Connection: %s\r\n" % connection
        ]
        if self.chunked:
            headers.append("Transfer-Encoding: chunked\r\n")
        return headers

    def send_headers(self):
        if self.headers_sent:
            return
        tosend = self.default_headers()
        tosend.extend(["%s: %s\r\n" % (k, v) for k, v in self.headers])

        header_str = "%s\r\n" % "".join(tosend)
        write(self.sock, to_bytestring(header_str, "ascii"))
        self.headers_sent = True

    def write(self, arg):
        self.send_headers()
        if not isinstance(arg, bytes):
            raise TypeError('%r is not a byte' % arg)
        arglen = len(arg)
        tosend = arglen
        if self.response_length is not None:
            if self.sent >= self.response_length:
                # Never write more than self.response_length bytes
                return

            tosend = min(self.response_length - self.sent, tosend)
            if tosend < arglen:
                arg = arg[:tosend]

        # Sending an empty chunk signals the end of the
        # response and prematurely closes the response
        if self.chunked and tosend == 0:
            return

        self.sent += tosend
        write(self.sock, arg, self.chunked)

    def can_sendfile(self):
        return sendfile is not None

    def sendfile(self, respiter):
        if not self.can_sendfile():
            return False

        if not has_fileno(respiter.filelike):
            return False

        fileno = respiter.filelike.fileno()
        try:
            offset = os.lseek(fileno, 0, os.SEEK_CUR)
            if self.response_length is None:
                filesize = os.fstat(fileno).st_size

                # The file may be special and sendfile will fail.
                # It may also be zero-length, but that is okay.
                if filesize == 0:
                    return False

                nbytes = filesize - offset
            else:
                nbytes = self.response_length
        except (OSError, io.UnsupportedOperation):
            return False

        self.send_headers()

        if self.is_chunked():
            chunk_size = "%X\r\n" % nbytes
            self.sock.sendall(chunk_size.encode('utf-8'))

        sockno = self.sock.fileno()
        sent = 0

        while sent != nbytes:
            count = min(nbytes - sent, BLKSIZE)
            sent += sendfile(sockno, fileno, offset + sent, count)

        if self.is_chunked():
            self.sock.sendall(b"\r\n")

        os.lseek(fileno, offset, os.SEEK_SET)

        return True

    def write_file(self, respiter):
        if not self.sendfile(respiter):
            for item in respiter:
                self.write(item)

    def close(self):
        if not self.headers_sent:
            self.send_headers()
        if self.chunked:
            write_chunk(self.sock, b"")


##########
# Worker
##########


class WorkerTmp:

    def __init__(self, cfg):
        old_umask = os.umask(cfg.umask)
        fd, name = tempfile.mkstemp(prefix="wgunicorn-")

        # allows the process to write to the file
        chown(name, cfg.uid, cfg.gid)
        os.umask(old_umask)

        # unlink the file so we don't leak tempory files
        try:
            unlink(name)
            self._tmp = os.fdopen(fd, 'w+b', 1)
        except:
            os.close(fd)
            raise

        self.spinner = 0

    def notify(self):
        self.spinner = (self.spinner + 1) % 2
        os.fchmod(self._tmp.fileno(), self.spinner)

    def last_update(self):
        return os.fstat(self._tmp.fileno()).st_ctime

    def fileno(self):
        return self._tmp.fileno()

    def close(self):
        return self._tmp.close()


class Worker:

    SIGNALS = [
        signal.SIGABRT, signal.SIGHUP, signal.SIGQUIT, signal.SIGINT,
        signal.SIGTERM, signal.SIGUSR1, signal.SIGUSR2, signal.SIGWINCH,
        signal.SIGCHLD,
    ]

    PIPE = []

    def __init__(self, age, ppid, sockets, app, timeout, cfg, log):
        """\
        This is called pre-fork so it shouldn't do anything to the
        current process. If there's a need to make process wide
        changes you'll want to do that in ``self.init_process()``.
        """
        self.age = age
        self.ppid = ppid
        self.sockets = sockets
        self.app = app
        self.timeout = timeout
        self.cfg = cfg
        self.booted = False
        self.aborted = False

        self.nr = 0
        jitter = randint(0, cfg.max_requests_jitter)
        self.max_requests = cfg.max_requests + jitter or sys.maxsize
        self.alive = True
        self.log = log
        self.tmp = WorkerTmp(cfg)

    def __str__(self):
        return "<Worker %s>" % self.pid

    @property
    def pid(self):
        return os.getpid()

    def notify(self):
        """\
        Your worker subclass must arrange to have this method called
        once every ``self.timeout`` seconds. If you fail in accomplishing
        this task, the master process will murder your workers.
        """
        self.tmp.notify()

    def init_process(self):
        """\
        If you override this method in a subclass, the last statement
        in the function should be to call this method with
        super(MyWorkerClass, self).init_process() so that the ``run()``
        loop is initiated.
        """

        # set environment' variables
        if self.cfg.env:
            for k, v in self.cfg.env.items():
                os.environ[k] = v

        set_owner_process(self.cfg.uid, self.cfg.gid,
                          initgroups=self.cfg.initgroups)

        # Reseed the random number generator
        seed()

        # For waking ourselves up
        self.PIPE = os.pipe()
        for p in self.PIPE:
            set_non_blocking(p)
            close_on_exec(p)

        # Prevent fd inheritance
        [close_on_exec(s) for s in self.sockets]
        close_on_exec(self.tmp.fileno())

        self.wait_fds = self.sockets + [self.PIPE[0]]

        self.log.close_on_exec()

        self.init_signals()

        self.load_wsgi()

        if self.cfg.post_worker_init:
            self.cfg.post_worker_init(self)

        # Enter main run loop
        self.booted = True
        self.run()

    def load_wsgi(self):
        try:
            self.wsgi = self.app.wsgi()
        except SyntaxError as e:
            if not self.cfg.reload:
                raise

            self.log.exception(e)

            # Fix from PR #1228:
            # Storing the traceback into exc_tb will create a circular
            # reference.
            # Per https://docs.python.org/2/library/sys.html#sys.exc_info
            # warning, delete the traceback after use.
            try:
                exc_type, exc_val, exc_tb = sys.exc_info()

                tb_string = traceback.format_tb(exc_tb)
                self.wsgi = make_fail_app(tb_string)
            finally:
                del exc_tb

    def init_signals(self):
        # reset signaling
        [signal.signal(s, signal.SIG_DFL) for s in self.SIGNALS]
        # init new signaling
        signal.signal(signal.SIGQUIT, self.handle_quit)
        signal.signal(signal.SIGTERM, self.handle_exit)
        signal.signal(signal.SIGINT, self.handle_quit)
        signal.signal(signal.SIGWINCH, self.handle_winch)
        signal.signal(signal.SIGUSR1, self.handle_usr1)
        signal.signal(signal.SIGABRT, self.handle_abort)

        # Don't let SIGTERM and SIGUSR1 disturb active requests
        # by interrupting system calls
        signal.siginterrupt(signal.SIGTERM, False)
        signal.siginterrupt(signal.SIGUSR1, False)

        if hasattr(signal, 'set_wakeup_fd'):
            signal.set_wakeup_fd(self.PIPE[1])

    def handle_usr1(self, sig, frame):
        self.log.reopen_files()

    def handle_exit(self, sig, frame):
        self.alive = False

    def handle_quit(self, sig, frame):
        self.alive = False

        if self.cfg.worker_int:
            self.cfg.worker_int(self)

        time.sleep(0.1)
        sys.exit(0)

    def handle_abort(self, sig, frame):
        self.alive = False

        if self.cfg.worker_abort:
            self.cfg.worker_abort(self)

        sys.exit(1)

    def handle_error(self, req, client, addr, exc):
        request_start = datetime.now()
        addr = addr or ('', -1)  # unix socket case
        if isinstance(
            exc, (
                InvalidRequestLine, InvalidRequestMethod, InvalidHTTPVersion,
                InvalidHeader, InvalidHeaderName, InvalidProxyLine,
                ForbiddenProxyRequest
            )
        ):
            status_int = 400
            reason = "Bad Request"

            if isinstance(exc, InvalidRequestLine):
                mesg = "Invalid Request Line '%s'" % str(exc)
            elif isinstance(exc, InvalidRequestMethod):
                mesg = "Invalid Method '%s'" % str(exc)
            elif isinstance(exc, InvalidHTTPVersion):
                mesg = "Invalid HTTP Version '%s'" % str(exc)
            elif isinstance(exc, (InvalidHeaderName, InvalidHeader,)):
                mesg = "%s" % str(exc)
                if not req and hasattr(exc, "req"):
                    req = exc.req  # for access log
            elif isinstance(exc, InvalidProxyLine):
                mesg = "'%s'" % str(exc)
            elif isinstance(exc, ForbiddenProxyRequest):
                reason = "Forbidden"
                mesg = "Request forbidden"
                status_int = 403

            msg = "Invalid request from ip={ip}: {error}"
            self.log.debug(msg.format(ip=addr[0], error=str(exc)))
        else:
            if hasattr(req, "uri"):
                self.log.exception("Error handling request %s", req.uri)
            status_int = 500
            reason = "Internal Server Error"
            mesg = ""

        if req is not None:
            request_time = datetime.now() - request_start
            environ = default_environ(req, client, self.cfg)
            environ['REMOTE_ADDR'] = addr[0]
            environ['REMOTE_PORT'] = str(addr[1])
            resp = Response(req, client, self.cfg)
            resp.status = "%s %s" % (status_int, reason)
            resp.response_length = len(mesg)
            self.log.access(resp, req, environ, request_time)

        try:
            write_error(client, status_int, reason, mesg)
        except:
            self.log.debug("Failed to send error message.")

    def handle_winch(self, sig, fname):
        # Ignore SIGWINCH in worker. Fixes a crash on OpenBSD.
        self.log.debug("worker: SIGWINCH ignored.")


class StopWaiting(Exception):
    """ exception raised to stop waiting for a connnection """


class SyncWorker(Worker):

    def accept(self, listener):
        client, addr = listener.accept()
        client.setblocking(1)
        close_on_exec(client)
        self.handle(listener, client, addr)

    def wait(self, timeout):
        try:
            self.notify()
            ret = select.select(self.wait_fds, [], [], timeout)
            if ret[0]:
                if self.PIPE[0] in ret[0]:
                    os.read(self.PIPE[0], 1)
                return ret[0]

        except select.error as e:
            if e.args[0] == errno.EINTR:
                return self.sockets
            if e.args[0] == errno.EBADF:
                if self.nr < 0:
                    return self.sockets
                else:
                    raise StopWaiting
            raise

    def is_parent_alive(self):
        # If our parent changed then we shut down.
        if self.ppid != os.getppid():
            self.log.info("Parent changed, shutting down: %s", self)
            return False
        return True

    def run_for_one(self, timeout):
        listener = self.sockets[0]
        while self.alive:
            self.notify()

            # Accept a connection. If we get an error telling us
            # that no connection is waiting we fall down to the
            # select which is where we'll wait for a bit for new
            # workers to come give us some love.
            try:
                self.accept(listener)
                # Keep processing clients until no one is waiting. This
                # prevents the need to select() for every client that we
                # process.
                continue

            except EnvironmentError as e:
                if e.errno not in (errno.EAGAIN, errno.ECONNABORTED,
                                   errno.EWOULDBLOCK):
                    raise

            if not self.is_parent_alive():
                return

            try:
                self.wait(timeout)
            except StopWaiting:
                return

    def run_for_multiple(self, timeout):
        while self.alive:
            self.notify()

            try:
                ready = self.wait(timeout)
            except StopWaiting:
                return

            if ready is not None:
                for listener in ready:
                    if listener == self.PIPE[0]:
                        continue

                    try:
                        self.accept(listener)
                    except EnvironmentError as e:
                        if e.errno not in (errno.EAGAIN, errno.ECONNABORTED,
                                           errno.EWOULDBLOCK):
                            raise

            if not self.is_parent_alive():
                return

    def run(self):
        # if no timeout is given the worker will never wait and will
        # use the CPU for nothing. This minimal timeout prevent it.
        timeout = self.timeout or 0.5

        # self.socket appears to lose its blocking status after
        # we fork in the arbiter. Reset it here.
        for s in self.sockets:
            s.setblocking(0)

        if len(self.sockets) > 1:
            self.run_for_multiple(timeout)
        else:
            self.run_for_one(timeout)

    def handle(self, listener, client, addr):
        req = None
        try:
            parser = RequestParser(self.cfg, client)
            req = next(parser)
            self.handle_request(listener, req, client, addr)
        except NoMoreData as e:
            self.log.debug("Ignored premature client disconnection. %s", e)
        except StopIteration as e:
            self.log.debug("Closing connection. %s", e)
        except EnvironmentError as e:
            if e.errno not in (errno.EPIPE, errno.ECONNRESET):
                self.log.exception("Socket error processing request.")
            else:
                if e.errno == errno.ECONNRESET:
                    self.log.debug("Ignoring connection reset")
                else:
                    self.log.debug("Ignoring EPIPE")
        except Exception as e:
            self.handle_error(req, client, addr, e)
        finally:
            close(client)

    def handle_request(self, listener, req, client, addr):
        environ = {}
        resp = None
        try:
            if self.cfg.pre_request:
                self.cfg.pre_request(self, req)

            request_start = datetime.now()
            resp, environ = create(req, client, addr, listener.getsockname(),
                                   self.cfg)
            # Force the connection closed until someone shows
            # a buffering proxy that supports Keep-Alive to
            # the backend.
            resp.force_close()
            self.nr += 1
            if self.nr >= self.max_requests:
                self.log.info("Autorestarting worker after current request.")
                self.alive = False
            respiter = self.wsgi(environ, resp.start_response)
            try:
                if isinstance(respiter, environ['wsgi.file_wrapper']):
                    resp.write_file(respiter)
                else:
                    for item in respiter:
                        resp.write(item)
                resp.close()
                request_time = datetime.now() - request_start
                self.log.access(resp, req, environ, request_time)
            finally:
                if hasattr(respiter, "close"):
                    respiter.close()
        except EnvironmentError:
            # pass to next try-except level
            reraise(*sys.exc_info())
        except Exception:
            if resp and resp.headers_sent:
                # If the requests have already been sent, we should close the
                # connection to indicate the error.
                self.log.exception("Error handling request")
                try:
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                except EnvironmentError:
                    pass
                raise StopIteration()
            raise
        finally:
            try:
                if self.cfg.post_request:
                    self.cfg.post_request(self, req, environ, resp)
            except Exception:
                self.log.exception("Exception in post_request hook")


###########
# Arbiter
###########

class Arbiter:
    """
    Arbiter maintain the workers processes alive. It launches or
    kills them if needed. It also manages application reloading
    via SIGHUP/USR2.
    """

    # A flag indicating if a worker failed to
    # to boot. If a worker process exist with
    # this error code, the arbiter will terminate.
    WORKER_BOOT_ERROR = 3

    # A flag indicating if an application failed to be loaded
    APP_LOAD_ERROR = 4

    START_CTX = {}

    LISTENERS = []
    WORKERS = {}
    PIPE = []

    SIG_QUEUE = []

    SIGNALS = [
        signal.SIGHUP, signal.SIGQUIT, signal.SIGINT, signal.SIGTERM,
        signal.SIGTTIN, signal.SIGTTOU, signal.SIGUSR1, signal.SIGUSR2,
        signal.SIGWINCH,
    ]

    SIG_NAMES = {
        signal.SIGABRT: 'abrt', signal.SIGALRM: 'alrm', signal.SIGBUS: 'bus',
        signal.SIGCHLD: 'chld', signal.SIGCLD: 'cld', signal.SIGCONT: 'cont',
        signal.SIGFPE: 'fpe', signal.SIGHUP: 'hup', signal.SIGILL: 'ill',
        signal.SIGINT: 'int', signal.SIGIO: 'io', signal.SIGIOT: 'iot',
        signal.SIGKILL: 'kill', signal.SIGPIPE: 'pipe', signal.SIGPOLL: 'poll',
        signal.SIGPROF: 'prof', signal.SIGPWR: 'pwr', signal.SIGQUIT: 'quit',
        signal.SIGRTMAX: 'rtmax', signal.SIGRTMIN: 'rtmin',
        signal.SIGSEGV: 'segv', signal.SIGSTOP: 'stop', signal.SIGSYS: 'sys',
        signal.SIGTERM: 'term', signal.SIGTRAP: 'trap', signal.SIGTSTP: 'tstp',
        signal.SIGTTIN: 'ttin', signal.SIGTTOU: 'ttou', signal.SIGURG: 'urg',
        signal.SIGUSR1: 'usr1', signal.SIGUSR2: 'usr2',
        signal.SIGVTALRM: 'vtalrm', signal.SIGWINCH: 'winch',
        signal.SIGXCPU: 'xcpu', signal.SIGXFSZ: 'xfsz',
    }

    def __init__(self, app):
        os.environ["SERVER_SOFTWARE"] = SERVER_SOFTWARE

        self._num_workers = None
        self._last_logged_active_worker_count = None
        self.log = None

        self.setup(app)

        self.pidfile = None
        self.worker_age = 0
        self.reexec_pid = 0
        self.master_pid = 0
        self.master_name = "Master"

        cwd = getcwd()

        args = sys.argv[:]
        args.insert(0, sys.executable)

        # init start context
        self.START_CTX = {
            "args": args,
            "cwd": cwd,
            0: sys.executable
        }

    def _get_num_workers(self):
        return self._num_workers

    def _set_num_workers(self, value):
        old_value = self._num_workers
        self._num_workers = value

        if self.cfg.nworkers_changed:
            self.cfg.nworkers_changed(self, value, old_value)

    num_workers = property(_get_num_workers, _set_num_workers)

    def setup(self, app):
        self.app = app
        self.cfg = app.cfg

        if self.log is None:
            self.log = Logger(app.cfg)

        # reopen files
        if 'GUNICORN_FD' in os.environ:
            self.log.reopen_files()

        self.address = self.cfg.address
        self.num_workers = self.cfg.workers
        self.timeout = self.cfg.timeout
        self.proc_name = self.cfg.proc_name

        self.log.debug('Current configuration:\n{0}'.format('TODO'))  # TODO

        # set enviroment' variables
        if self.cfg.env:
            for k, v in self.cfg.env.items():
                os.environ[k] = v

    def start(self):
        """\
        Initialize the arbiter. Start listening and set pidfile if needed.
        """
        self.log.info("Starting gunicorn %s", __version__)

        if 'GUNICORN_PID' in os.environ:
            self.master_pid = int(os.environ.get('GUNICORN_PID'))
            self.proc_name = self.proc_name + ".2"
            self.master_name = "Master.2"

        self.pid = os.getpid()
        if self.cfg.pidfile is not None:
            pidname = self.cfg.pidfile
            if self.master_pid != 0:
                pidname += ".2"
            self.pidfile = Pidfile(pidname)
            self.pidfile.create(self.pid)

        if self.cfg.on_starting:
            self.cfg.on_starting(self)

        self.init_signals()
        if not self.LISTENERS:
            self.LISTENERS = create_sockets(self.cfg, self.log)

        listeners_str = ",".join([str(l) for l in self.LISTENERS])
        self.log.debug("Arbiter booted")
        self.log.info("Listening at: %s (%s)", listeners_str, self.pid)

        if self.cfg.when_ready:
            self.cfg.when_ready(self)

    def init_signals(self):
        """\
        Initialize master signal handling. Most of the signals
        are queued. Child signals only wake up the master.
        """
        # close old PIPE
        if self.PIPE:
            [os.close(p) for p in self.PIPE]

        # initialize the pipe
        self.PIPE = pair = os.pipe()
        for p in pair:
            set_non_blocking(p)
            close_on_exec(p)

        self.log.close_on_exec()

        # initialize all signals
        [signal.signal(s, self.signal) for s in self.SIGNALS]
        signal.signal(signal.SIGCHLD, self.handle_chld)

    def signal(self, sig, frame):
        if len(self.SIG_QUEUE) < 5:
            self.SIG_QUEUE.append(sig)
            self.wakeup()

    def run(self):
        "Main master loop."
        self.start()
        _setproctitle("master [%s]" % self.proc_name)

        try:
            self.manage_workers()

            while True:
                self.maybe_promote_master()

                sig = self.SIG_QUEUE.pop(0) if len(self.SIG_QUEUE) else None
                if sig is None:
                    self.sleep()
                    self.murder_workers()
                    self.manage_workers()
                    continue

                if sig not in self.SIG_NAMES:
                    self.log.info("Ignoring unknown signal: %s", sig)
                    continue

                signame = self.SIG_NAMES.get(sig)
                handler = getattr(self, "handle_%s" % signame, None)
                if not handler:
                    self.log.error("Unhandled signal: %s", signame)
                    continue
                self.log.info("Handling signal: %s", signame)
                handler()
                self.wakeup()
        except StopIteration:
            self.halt()
        except KeyboardInterrupt:
            self.halt()
        except HaltServer as inst:
            self.halt(reason=inst.reason, exit_status=inst.exit_status)
        except SystemExit:
            raise
        except Exception:
            self.log.info("Unhandled exception in main loop",
                          exc_info=True)
            self.stop(False)
            if self.pidfile is not None:
                self.pidfile.unlink()
            sys.exit(-1)

    def handle_chld(self, sig, frame):
        """SIGCHLD handling"""
        self.reap_workers()
        self.wakeup()

    def handle_hup(self):
        """\
        HUP handling.
        - Reload configuration
        - Start the new worker processes with a new configuration
        - Gracefully shutdown the old worker processes
        """
        self.log.info("Hang up: %s", self.master_name)
        self.reload()

    def handle_term(self):
        """SIGTERM handling"""
        raise StopIteration

    def handle_int(self):
        """SIGINT handling"""
        self.stop(False)
        raise StopIteration

    def handle_quit(self):
        """SIGQUIT handling"""
        self.stop(False)
        raise StopIteration

    def handle_ttin(self):
        """\
        SIGTTIN handling.
        Increases the number of workers by one.
        """
        self.num_workers += 1
        self.manage_workers()

    def handle_ttou(self):
        """\
        SIGTTOU handling.
        Decreases the number of workers by one.
        """
        if self.num_workers <= 1:
            return
        self.num_workers -= 1
        self.manage_workers()

    def handle_usr1(self):
        """\
        SIGUSR1 handling.
        Kill all workers by sending them a SIGUSR1
        """
        self.log.reopen_files()
        self.kill_workers(signal.SIGUSR1)

    def handle_usr2(self):
        """\
        SIGUSR2 handling.
        Creates a new master/worker set as a slave of the current
        master without affecting old workers. Use this to do live
        deployment with the ability to backout a change.
        """
        self.reexec()

    def handle_winch(self):
        "SIGWINCH handling"
        if self.cfg.daemon:
            self.log.info("graceful stop of workers")
            self.num_workers = 0
            self.kill_workers(signal.SIGTERM)
        else:
            self.log.debug("SIGWINCH ignored. Not daemonized")

    def maybe_promote_master(self):
        if self.master_pid == 0:
            return

        if self.master_pid != os.getppid():
            self.log.info("Master has been promoted.")
            # reset master infos
            self.master_name = "Master"
            self.master_pid = 0
            self.proc_name = self.cfg.proc_name
            del os.environ['GUNICORN_PID']
            # rename the pidfile
            if self.pidfile is not None:
                self.pidfile.rename(self.cfg.pidfile)
            # reset proctitle
            _setproctitle("master [%s]" % self.proc_name)

    def wakeup(self):
        """\
        Wake up the arbiter by writing to the PIPE
        """
        try:
            os.write(self.PIPE[1], b'.')
        except IOError as e:
            if e.errno not in [errno.EAGAIN, errno.EINTR]:
                raise

    def halt(self, reason=None, exit_status=0):
        """ halt arbiter """
        self.stop()
        self.log.info("Shutting down: %s", self.master_name)
        if reason is not None:
            self.log.info("Reason: %s", reason)
        if self.pidfile is not None:
            self.pidfile.unlink()

        if self.cfg.on_exit:
            self.cfg.on_exit(self)

        sys.exit(exit_status)

    def sleep(self):
        """\
        Sleep until PIPE is readable or we timeout.
        A readable PIPE means a signal occurred.
        """
        try:
            ready = select.select([self.PIPE[0]], [], [], 1.0)
            if not ready[0]:
                return
            while os.read(self.PIPE[0], 1):
                pass
        except select.error as e:
            if e.args[0] not in [errno.EAGAIN, errno.EINTR]:
                raise
        except OSError as e:
            if e.errno not in [errno.EAGAIN, errno.EINTR]:
                raise
        except KeyboardInterrupt:
            sys.exit()

    def stop(self, graceful=True):
        """\
        Stop workers

        :attr graceful: boolean, If True (the default) workers will be
        killed gracefully  (ie. trying to wait for the current connection)
        """

        if self.reexec_pid == 0 and self.master_pid == 0:
            for l in self.LISTENERS:
                l.close()

        self.LISTENERS = []
        sig = signal.SIGTERM
        if not graceful:
            sig = signal.SIGQUIT
        limit = time.time() + self.cfg.graceful_timeout
        # instruct the workers to exit
        self.kill_workers(sig)
        # wait until the graceful timeout
        while self.WORKERS and time.time() < limit:
            time.sleep(0.1)

        self.kill_workers(signal.SIGKILL)

    def reexec(self):
        """\
        Relaunch the master and workers.
        """
        if self.reexec_pid != 0:
            self.log.warning("USR2 signal ignored. Child exists.")
            return

        if self.master_pid != 0:
            self.log.warning("USR2 signal ignored. Parent exists.")
            return

        master_pid = os.getpid()
        self.reexec_pid = os.fork()
        if self.reexec_pid != 0:
            return

        if self.cfg.pre_exec:
            self.cfg.pre_exec(self)

        environ = self.cfg.env_orig.copy()
        fds = [l.fileno() for l in self.LISTENERS]
        environ['GUNICORN_FD'] = ",".join([str(fd) for fd in fds])
        environ['GUNICORN_PID'] = str(master_pid)

        os.chdir(self.START_CTX['cwd'])

        # exec the process using the original environment
        os.execvpe(self.START_CTX[0], self.START_CTX['args'], environ)

    def reload(self):
        old_address = self.cfg.address

        # reset old environment
        for k in self.cfg.env:
            if k in self.cfg.env_orig:
                # reset the key to the value it had before
                # we launched gunicorn
                os.environ[k] = self.cfg.env_orig[k]
            else:
                # delete the value set by gunicorn
                try:
                    del os.environ[k]
                except KeyError:
                    pass

        # reload conf
        self.app.reload()
        self.setup(self.app)

        # reopen log files
        self.log.reopen_files()

        # do we need to change listener ?
        if old_address != self.cfg.address:
            # close all listeners
            [l.close() for l in self.LISTENERS]
            # init new listeners
            self.LISTENERS = create_sockets(self.cfg, self.log)
            listeners_str = ",".join([str(l) for l in self.LISTENERS])
            self.log.info("Listening at: %s", listeners_str)

        # do some actions on reload
        if self.cfg.on_reload:
            self.cfg.on_reload(self)

        # unlink pidfile
        if self.pidfile is not None:
            self.pidfile.unlink()

        # create new pidfile
        if self.cfg.pidfile is not None:
            self.pidfile = Pidfile(self.cfg.pidfile)
            self.pidfile.create(self.pid)

        # set new proc_name
        _setproctitle("master [%s]" % self.proc_name)

        # spawn new workers
        for i in range(self.cfg.workers):
            self.spawn_worker()

        # manage workers
        self.manage_workers()

    def murder_workers(self):
        """\
        Kill unused/idle workers
        """
        if not self.timeout:
            return
        workers = list(self.WORKERS.items())
        for (pid, worker) in workers:
            try:
                if time.time() - worker.tmp.last_update() <= self.timeout:
                    continue
            except (OSError, ValueError):
                continue

            if not worker.aborted:
                self.log.critical("WORKER TIMEOUT (pid:%s)", pid)
                worker.aborted = True
                self.kill_worker(pid, signal.SIGABRT)
            else:
                self.kill_worker(pid, signal.SIGKILL)

    def reap_workers(self):
        """\
        Reap workers to avoid zombie processes
        """
        try:
            while True:
                wpid, status = os.waitpid(-1, os.WNOHANG)
                if not wpid:
                    break
                if self.reexec_pid == wpid:
                    self.reexec_pid = 0
                else:
                    # A worker said it cannot boot. We'll shutdown
                    # to avoid infinite start/stop cycles.
                    exitcode = status >> 8
                    if exitcode == self.WORKER_BOOT_ERROR:
                        reason = "Worker failed to boot."
                        raise HaltServer(reason, self.WORKER_BOOT_ERROR)
                    if exitcode == self.APP_LOAD_ERROR:
                        reason = "App failed to load."
                        raise HaltServer(reason, self.APP_LOAD_ERROR)
                    worker = self.WORKERS.pop(wpid, None)
                    if not worker:
                        continue
                    worker.tmp.close()
        except OSError as e:
            if e.errno != errno.ECHILD:
                raise

    def manage_workers(self):
        """\
        Maintain the number of workers by spawning or killing
        as required.
        """
        if len(self.WORKERS.keys()) < self.num_workers:
            self.spawn_workers()

        workers = self.WORKERS.items()
        workers = sorted(workers, key=lambda w: w[1].age)
        while len(workers) > self.num_workers:
            (pid, _) = workers.pop(0)
            self.kill_worker(pid, signal.SIGTERM)

        active_worker_count = len(workers)
        if self._last_logged_active_worker_count != active_worker_count:
            self._last_logged_active_worker_count = active_worker_count
            self.log.debug("{0} workers".format(active_worker_count),
                           extra={"metric": "gunicorn.workers",
                                  "value": active_worker_count,
                                  "mtype": "gauge"})

    def spawn_worker(self):
        self.worker_age += 1
        worker = SyncWorker(self.worker_age, self.pid, self.LISTENERS,
                            self.app, self.timeout / 2.0, self.cfg, self.log)

        if self.cfg.pre_fork:
            self.cfg.pre_fork(self, worker)

        pid = os.fork()
        if pid != 0:
            self.WORKERS[pid] = worker
            return pid

        # Process Child
        worker_pid = os.getpid()
        try:
            _setproctitle("worker [%s]" % self.proc_name)
            self.log.info("Booting worker with pid: %s", worker_pid)

            if self.cfg.post_fork:
                self.cfg.post_fork(self, worker)

            worker.init_process()
            sys.exit(0)
        except SystemExit:
            raise
        except AppImportError as e:
            self.log.debug("Exception while loading the application",
                           exc_info=True)
            print("%s" % e, file=sys.stderr)
            sys.stderr.flush()
            sys.exit(self.APP_LOAD_ERROR)
        except:
            self.log.exception("Exception in worker process"),
            if not worker.booted:
                sys.exit(self.WORKER_BOOT_ERROR)
            sys.exit(-1)
        finally:
            self.log.info("Worker exiting (pid: %s)", worker_pid)
            try:
                worker.tmp.close()

                if self.cfg.worker_exit:
                    self.cfg.worker_exit(self, worker)
            except:
                self.log.warning(
                    "Exception during worker exit:\n%s", traceback.format_exc()
                )

    def spawn_workers(self):
        """\
        Spawn new workers as needed.

        This is where a worker process leaves the main loop
        of the master process.
        """

        for i in range(self.num_workers - len(self.WORKERS.keys())):
            self.spawn_worker()
            time.sleep(0.1 * random.random())

    def kill_workers(self, sig):
        """\
        Kill all workers with the signal `sig`
        :attr sig: `signal.SIG*` value
        """
        worker_pids = list(self.WORKERS.keys())
        for pid in worker_pids:
            self.kill_worker(pid, sig)

    def kill_worker(self, pid, sig):
        """\
        Kill a worker

        :attr pid: int, worker pid
        :attr sig: `signal.SIG*` value
         """
        try:
            os.kill(pid, sig)
        except OSError as e:
            if e.errno == errno.ESRCH:
                try:
                    worker = self.WORKERS.pop(pid)
                    worker.tmp.close()

                    if self.cfg.worker_exit:
                        self.cfg.worker_exit(self, worker)

                    return
                except (KeyError, OSError):
                    return
            raise


###############
# Application
###############

class BaseApplication:
    """
    An application interface for configuring and loading
    the various necessities for any given web framework.
    """
    def __init__(self, usage=None, prog=None):
        self.usage = usage
        self.cfg = Config()
        self.callable = None
        self.prog = prog
        self.logger = None
        self.do_load_config()

    def do_load_config(self):
        """
        Loads the configuration
        """
        try:
            self.load_config()
        except Exception as e:
            print("\nError: %s" % str(e), file=sys.stderr)
            sys.stderr.flush()
            sys.exit(1)

    def reload(self):
        self.do_load_config()

    def wsgi(self):
        if self.callable is None:
            self.callable = self.load()
        return self.callable

    def run(self):
        try:
            Arbiter(self).run()
        except RuntimeError as e:
            print("\nError: %s\n" % e, file=sys.stderr)
            sys.stderr.flush()
            sys.exit(1)


class Application(BaseApplication):

    def load_config(self):
        kwargs = {
            "usage": self.usage,
            "prog": self.prog
        }
        parser = argparse.ArgumentParser(**kwargs)
        parser.add_argument(
            "-v", "--version",
            action="version", default=argparse.SUPPRESS,
            version="%(prog)s (version " + __version__ + ")\n",
            help="show program's version number and exit"
        )
        parser.add_argument("args", nargs="*", help=argparse.SUPPRESS)

        # parse console args
        args = parser.parse_args()

        # optional settings from apps
        self.init(parser, args, args.args)

    def run(self):
        if self.cfg.check_config:
            try:
                self.load()
            except:
                msg = "\nError while loading the application:\n"
                print(msg, file=sys.stderr)
                traceback.print_exc()
                sys.stderr.flush()
                sys.exit(1)
            sys.exit(0)

        if self.cfg.daemon:
            daemonize(self.cfg.enable_stdio_inheritance)

        # set python paths
        if self.cfg.pythonpath and self.cfg.pythonpath is not None:
            paths = self.cfg.pythonpath.split(",")
            for path in paths:
                pythonpath = os.path.abspath(path)
                if pythonpath not in sys.path:
                    sys.path.insert(0, pythonpath)

        super(Application, self).run()


class WSGIApplication(Application):
    def init(self, parser, opts, args):
        if len(args) < 1:
            parser.error("No application module specified.")

        self.cfg.default_proc_name = args[0]
        self.app_uri = args[0]

    def chdir(self):
        # chdir to the configured path before loading,
        # default is the current dir
        os.chdir(self.cfg.chdir)

        # add the path to sys.path
        sys.path.insert(0, self.cfg.chdir)

    def load_wsgiapp(self):
        self.chdir()

        # load the app
        return import_app(self.app_uri)

    def load(self):
        return self.load_wsgiapp()


def run():
    WSGIApplication("%(prog)s [OPTIONS] [APP_MODULE]").run()


if __name__ == '__main__':
    run()
