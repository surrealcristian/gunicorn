# -*- coding: utf-8 -
#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

import os
import sys
import pytest

from gunicorn import Config
from gunicorn import Application
from gunicorn import SyncWorker
from gunicorn import Logger


dirname = os.path.dirname(__file__)


def cfg_module():
    return 'config.test_cfg'


def cfg_file():
    return os.path.join(dirname, "config", "test_cfg.py")


class AltArgs(object):
    def __init__(self, args=None):
        self.args = args or []
        self.orig = sys.argv

    def __enter__(self):
        sys.argv = self.args

    def __exit__(self, exc_type, exc_inst, traceback):
        sys.argv = self.orig


class NoConfigApp(Application):
    def __init__(self):
        super(NoConfigApp, self).__init__("no_usage", prog="gunicorn_test")

    def init(self, parser, opts, args):
        pass

    def load(self):
        pass


def test_pos_int_validation():
    c = Config()
    assert c.workers == 1
    c.workers = 4
    assert c.workers == 4


def test_str_validation():
    c = Config()
    assert c.proc_name == "gunicorn"
    c.proc_name_internal = "foo"
    assert c.proc_name == "foo"


def test_str_to_list_validation():
    c = Config()
    assert c.forwarded_allow_ips == ["127.0.0.1"]


def test_callable_validation():
    c = Config()

    def func(a, b):
        pass

    c.pre_fork = func
    assert c.pre_fork == func


@pytest.fixture
def create_config_file(request):
    default_config = os.path.join(os.path.abspath(os.getcwd()),
                                  'gunicorn.conf.py')
    with open(default_config, 'w+') as default:
        default.write("bind='0.0.0.0:9090'")

    def fin():
        os.unlink(default_config)
    request.addfinalizer(fin)

    return default


def test_post_request():
    c = Config()

    def post_request_4(worker, req, environ, resp):
        return 4

    def post_request_3(worker, req, environ, resp=None):
        return 3

    def post_request_2(worker, req, environ=None, resp=None):
        return 2

    c.post_request = post_request_4
    assert c.post_request(1, 2, 3, 4) == 4

    c.post_request = post_request_3
    assert c.post_request(1, 2, 3, 4) == 3

    c.post_request = post_request_2
    assert c.post_request(1, 2, 3, 4) == 2


def test_nworkers_changed():
    c = Config()

    def nworkers_changed_3(server, new_value, old_value):
        return 3

    c.nworkers_changed = nworkers_changed_3
    assert c.nworkers_changed(1, 2, 3) == 3


class MyLogger(Logger):
    # dummy custom logger class for testing
    pass


def test_always_use_configured_logger():
    c = Config()
    c.logger_class_str = __name__ + '.MyLogger'
    assert c.logger_class == MyLogger
