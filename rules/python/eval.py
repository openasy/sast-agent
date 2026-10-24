def run(request):
    # ruleid: openasy.python.eval
    eval(request.args["expr"])
    # ruleid: openasy.python.eval
    exec(request.form.get("code"))
    # ok: openasy.python.eval
    eval("1 + 1")
