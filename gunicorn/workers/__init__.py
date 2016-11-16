# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

import sys

# supported gunicorn workers.
SUPPORTED_WORKERS = {
    "sync": "gunicorn.workers.sync.SyncWorker",
    "gthread": "gunicorn.workers.gthread.ThreadWorker",
}
