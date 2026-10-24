function run(req) {
  // ruleid: openasy.javascript.eval
  eval(req.query.expr);
  // ruleid: openasy.javascript.eval
  const f = new Function("a", req.body.code);
  // ruleid: openasy.javascript.eval
  setTimeout("go(" + req.query.n + ")", 10);
  // ok: openasy.javascript.eval
  eval("1 + 1");
  // ok: openasy.javascript.eval
  setTimeout(() => go(req.query.n), 10);
  // ok: openasy.javascript.eval
  setInterval(function () {
    tick();
  }, 1000);
  return f;
}
