# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

import sys

try:
    import aiohttp  # NOQA
except ImportError:
    raise RuntimeError("You need aiohttp installed to use this worker.")
else:
    from gunicorn.workers._gaiohttp import AiohttpWorker
    __all__ = ['AiohttpWorker']
