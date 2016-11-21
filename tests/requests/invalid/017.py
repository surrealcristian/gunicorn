from gunicorn import Config
from gunicorn import LimitRequestHeaders

cfg = Config()
request = LimitRequestHeaders
