from gunicorn import Config
from gunicorn import InvalidProxyLine

cfg = Config()
cfg.set('proxy_protocol', True)

request = InvalidProxyLine
