from gunicorn import Config
from gunicorn import LimitRequestHeaders

request = LimitRequestHeaders
cfg = Config()
cfg.set('limit_request_field_size', 14)
