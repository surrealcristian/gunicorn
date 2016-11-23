from gunicorn import Config

cfg = Config()
cfg.proxy_protocol = True

request = {
    "method": "GET",
    "uri": uri("/stuff/here?foo=bar"),
    "version": (1, 0),
    "headers": [
        ("SERVER", "http://127.0.0.1:5984"),
        ("CONTENT-TYPE", "application/json"),
        ("CONTENT-LENGTH", "14")
    ],
    "body": b'{"nom": "nom"}'
}
