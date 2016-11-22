# -*- coding: utf-8 -
#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

import os

try:
    import unittest.mock as mock
except ImportError:
    import mock

from gunicorn import BaseApplication
from gunicorn import Arbiter


class DummyApplication(BaseApplication):
    """
    Dummy application that has an default configuration.
    """

    def init(self, parser, opts, args):
        """No-op"""

    def load(self):
        """No-op"""

    def load_config(self):
        """No-op"""


def test_arbiter_shutdown_closes_listeners():
    arbiter = Arbiter(DummyApplication())
    listener1 = mock.Mock()
    listener2 = mock.Mock()
    arbiter.LISTENERS = [listener1, listener2]
    arbiter.stop()
    listener1.close.assert_called_with()
    listener2.close.assert_called_with()


def verify_env_vars():
    assert os.getenv('SOME_PATH') == '/tmp/something'
    assert os.getenv('OTHER_PATH') == '/tmp/something/else'
