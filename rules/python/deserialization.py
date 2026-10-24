import pickle

import yaml


def read(data, stream):
    # ruleid: openasy.python.unsafe-deserialization
    obj = pickle.loads(data)
    # ruleid: openasy.python.unsafe-deserialization
    cfg = yaml.load(stream)
    # ok: openasy.python.unsafe-deserialization
    safe = yaml.load(stream, Loader=yaml.SafeLoader)
    # ok: openasy.python.unsafe-deserialization
    also = yaml.safe_load(stream)
    return obj, cfg, safe, also
