from gunicorn import Config
from gunicorn import InvalidProxyLine

cfg = Config()
cfg.proxy_protocol = True

request = InvalidProxyLine
