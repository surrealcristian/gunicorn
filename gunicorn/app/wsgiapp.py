# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

import os
import sys

from gunicorn.app.base import Application
from gunicorn import util


class WSGIApplication(Application):
    def init(self, parser, opts, args):
        if len(args) < 1:
            parser.error("No application module specified.")

        self.cfg.set("default_proc_name", args[0])
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
        return util.import_app(self.app_uri)

    def load(self):
        return self.load_wsgiapp()


def run():
    """\
    The ``gunicorn`` command line runner for launching Gunicorn with
    generic WSGI applications.
    """
    from gunicorn.app.wsgiapp import WSGIApplication
    WSGIApplication("%(prog)s [OPTIONS] [APP_MODULE]").run()


if __name__ == '__main__':
    run()
