const cp = require("child_process");
const { exec, execFile } = require("child_process");
function run(req) {
  // ruleid: openasy.javascript.command-injection
  cp.exec(`git log ${req.query.ref}`);
  // ruleid: openasy.javascript.command-injection
  exec("ping -c 1 " + req.query.host, () => {});
  // ruleid: openasy.javascript.command-injection
  cp.spawn("tar " + req.query.file, [], { shell: true });
  // ok: openasy.javascript.command-injection
  execFile("ping", ["-c", "1", req.query.host], () => {});
  // ok: openasy.javascript.command-injection
  cp.exec("git status");
}
