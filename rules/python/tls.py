import ssl

import requests


def get(url):
    # ruleid: openasy.python.tls-verification-off
    requests.get(url, verify=False)
    # ruleid: openasy.python.tls-verification-off
    ctx = ssl._create_unverified_context()
    # ok: openasy.python.tls-verification-off
    requests.get(url, timeout=5)
    return ctx
