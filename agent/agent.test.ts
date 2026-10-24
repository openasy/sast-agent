import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAgent } from "./agent.ts";
import { checkJob, gitEnv, runJob, type ScanOptions } from "./jobs.ts";
import { createKeyring } from "./kek.ts";
import { loadState } from "./state.ts";

const TOKEN = "github_pat_0123456789abcdefghijklmnop";
const RULES = new URL("../rules", import.meta.url).pathname;
const tmp = (p: string) => mkdtempSync(join(tmpdir(), `sast-agent-${p}-`));
const git = (cwd: string, ...args: string[]) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", ...args], { cwd, encoding: "utf8" }).trim();

/** A repository with a flaw at its second commit, which a scan of the first must not see. */
function repository() {
  const dir = tmp("repo");
  git(dir, "init", "--quiet", "--initial-branch=main");
  git(dir, "config", "uploadpack.allowAnySHA1InWant", "true");
  writeFileSync(join(dir, "a.js"), "export const add = (a, b) => a + b;\n");
  git(dir, "add", ".");
  git(dir, "commit", "--quiet", "-m", "one");
  const first = git(dir, "rev-parse", "HEAD");
  writeFileSync(join(dir, "b.js"), "export function run(req) {\n  eval(req.query.expr);\n}\n");
  git(dir, "add", ".");
  git(dir, "commit", "--quiet", "-m", "two");
  return { dir, url: `file://${dir}`, first, second: git(dir, "rev-parse", "HEAD") };
}

/** Opengrep for tests without it: records how it was run and writes one result per file it is given. */
function fakeOpengrep() {
  const dir = tmp("bin");
  const bin = join(dir, "opengrep");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const fs = require("fs");
const out = process.argv.find((a) => a.startsWith("--sarif-output=")).slice(15);
fs.writeFileSync(${JSON.stringify(join(dir, "call.json"))}, JSON.stringify({ args: process.argv.slice(2), env: process.env, files: fs.readdirSync(".").sort() }));
const results = fs.readdirSync(".").filter((f) => f.endsWith(".js")).map((f) => ({ ruleId: "x", locations: [{ physicalLocation: { artifactLocation: { uri: f } } }] }));
fs.writeFileSync(out, JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "Opengrep OSS" } }, results }] }));
`,
  );
  chmodSync(bin, 0o755);
  return { bin, call: () => JSON.parse(readFileSync(join(dir, "call.json"), "utf8")) as { args: string[]; env: Record<string, string>; files: string[] } };
}

let repo: ReturnType<typeof repository>;
let fake: ReturnType<typeof fakeOpengrep>;
let workDir: string;
const options = (over: Partial<ScanOptions> = {}): ScanOptions => ({
  workDir,
  opengrep: fake.bin,
  rulesDir: RULES,
  scanTimeoutMs: 60_000,
  cloneTimeoutMs: 60_000,
  memoryMb: 512,
  schemes: ["file:", "https:"],
  ...over,
});
const job = (over: Record<string, unknown> = {}) => ({
  id: "0b8c2d1e-0000-4000-8000-000000000001",
  repository: "acme/web",
  cloneUrl: repo.url,
  branch: "main",
  commit: repo.second,
  token: TOKEN,
  ruleSources: [],
  ...over,
});

beforeAll(() => {
  repo = repository();
  fake = fakeOpengrep();
  workDir = tmp("work");
});

describe("jobs from sast", () => {
  it.each([
    ["a clone URL that is not https", { cloneUrl: "ssh://git@github.com/acme/web.git" }],
    ["a clone URL with credentials in it", { cloneUrl: "https://x:y@github.com/acme/web.git" }],
    ["a branch git would read as an option", { branch: "--upload-pack=sh" }],
    ["a branch that leaves refs", { branch: "main/../../x" }],
    ["a commit that is not a hash", { commit: "HEAD" }],
    ["a token with a line break", { token: "a\nb" }],
    ["a rule source that is not https", { ruleSources: ["file:///etc"] }],
    ["an own rule whose name is a path", { ownRules: [{ name: "../x", yaml: "rules: []" }] }],
    ["a disabled rule that is an option", { disabledRules: ["--config=/etc"] }],
    ["more than 10 rule sources", { ruleSources: Array.from({ length: 11 }, (_, i) => `https://github.com/a/r${i}`) }],
  ])("refuses %s", (_, over) => {
    expect(() => checkJob({ ...job(), cloneUrl: "https://github.com/acme/web.git", ...over })).toThrow();
  });

  it("gives git the token only as a header in its environment, and no hooks or symlinks", () => {
    const env = gitEnv("/w", ["https:"], [["http.extraHeader", "Authorization: Basic x"]]);
    const config = Object.fromEntries(
      Array.from({ length: Number(env.GIT_CONFIG_COUNT) }, (_, i) => [env[`GIT_CONFIG_KEY_${i}`], env[`GIT_CONFIG_VALUE_${i}`]]),
    );
    expect(config).toMatchObject({
      "core.hooksPath": "/dev/null",
      "core.symlinks": "false",
      "protocol.allow": "never",
      "protocol.https.allow": "always",
      "http.extraHeader": "Authorization: Basic x",
    });
    expect(env).toMatchObject({ GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0" });
  });
});

describe("a scan", () => {
  it("scans exactly the queued commit, without the token in Opengrep's sight, and leaves nothing behind", async () => {
    const out = await runJob(job({ commit: repo.first }), options());
    expect(out).toMatchObject({ ok: true, findings: 1 });
    const call = fake.call();
    expect(call.files).toEqual([".git", "a.js"]);
    expect(call.args).toEqual(expect.arrayContaining(["scan", "--no-rewrite-rule-ids", "--config", RULES, "--max-memory=512", "."]));
    expect(JSON.stringify(call)).not.toContain(TOKEN);
    expect(readdirSync(workDir)).toEqual([]);
  });

  it("adds the rule files of a rule source, not its other YAML", async () => {
    const rules = tmp("rules");
    git(rules, "init", "--quiet", "--initial-branch=main");
    writeFileSync(join(rules, "mine.yaml"), "rules:\n  - id: acme.no-todo\n");
    writeFileSync(join(rules, "ci.yml"), "name: ci\non: push\n");
    git(rules, "add", ".");
    git(rules, "commit", "--quiet", "-m", "rules");
    expect(await runJob(job({ ruleSources: [`file://${rules}`] }), options())).toMatchObject({ ok: true, findings: 2 });
    const configs = fake.call().args.filter((_, i, a) => a[i - 1] === "--config");
    expect(configs[0]).toBe(RULES);
    expect(configs.slice(1).map((c) => c.split("/").pop())).toEqual(["mine.yaml"]);
  });

  it("adds the install's own rules, and skips the rules switched off", async () => {
    const yaml = "rules:\n  - id: acme.todo\n";
    expect(await runJob(job({ ownRules: [{ name: "todo", yaml }], disabledRules: ["openasy.javascript.eval"] }), options())).toMatchObject({ ok: true });
    const args = fake.call().args;
    const configs = args.filter((_, i, a) => a[i - 1] === "--config");
    expect(configs.at(-1)!.endsWith("/own-rules/todo.yaml")).toBe(true);
    expect(args).toContain("--exclude-rule=openasy.javascript.eval");
  });

  it("says why a scan failed, without the token, and still cleans up", async () => {
    const out = await runJob(job({ cloneUrl: `file://${repo.dir}-missing` }), options());
    expect(out).toMatchObject({ ok: false });
    expect(!out.ok && out.error).toMatch(/^Cloning acme\/web failed/);
    expect(JSON.stringify(out)).not.toContain(TOKEN);
    expect(await runJob(job(), options({ opengrep: "/nonexistent/opengrep" }))).toMatchObject({
      ok: false,
      error: expect.stringMatching(/Opengrep could not start/),
    });
    expect(await runJob({ id: "j", repository: "acme/web" }, options())).toMatchObject({ ok: false, error: expect.stringMatching(/refused the job/) });
    expect(readdirSync(workDir)).toEqual([]);
  });

  it("stops a scan at its time limit", async () => {
    const slow = join(tmp("slow"), "opengrep");
    writeFileSync(slow, "#!/bin/sh\nsleep 30\n");
    chmodSync(slow, 0o755);
    const out = await runJob(job(), options({ opengrep: slow, scanTimeoutMs: 300 }));
    expect(out).toMatchObject({ ok: false, error: expect.stringMatching(/Opengrep took longer than/) });
  });

  // The shipped rules with the real engine; CI installs the pinned Opengrep and sets OPENGREP_BIN.
  it.skipIf(!process.env.OPENGREP_BIN || !existsSync(process.env.OPENGREP_BIN))(
    "finds the flaw with Opengrep and the shipped rules",
    async () => {
      const out = await runJob(job(), options({ opengrep: process.env.OPENGREP_BIN! }));
      expect(out.ok).toBe(true);
      const sarif = JSON.parse(out.ok ? out.sarif.toString("utf8") : "{}");
      const results = sarif.runs[0].results.map((r: any) => `${r.ruleId} ${r.locations[0].physicalLocation.artifactLocation.uri}`);
      expect(results).toEqual(["openasy.javascript.eval b.js"]);
      // Switched off, the shipped rule reports nothing; an own rule reports what it matches.
      const own = "rules:\n  - id: acme.eval-anywhere\n    pattern: eval(...)\n    message: eval\n    languages: [javascript]\n    severity: WARNING\n";
      const again = await runJob(
        job({ ownRules: [{ name: "eval", yaml: own }], disabledRules: ["openasy.javascript.eval"] }),
        options({ opengrep: process.env.OPENGREP_BIN! }),
      );
      const ids = JSON.parse(again.ok ? again.sarif.toString("utf8") : "{}").runs[0].results.map((r: any) => r.ruleId);
      expect(ids).toEqual(["acme.eval-anywhere"]);
    },
    120_000,
  );
});

describe("the agent with sast", () => {
  const calls: Array<{ path: string; auth?: string; body: Buffer }> = [];
  let jobs: unknown[] = [];
  const server = createServer(async (req: IncomingMessage, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = req.headers["content-encoding"] === "gzip" ? gunzipSync(Buffer.concat(chunks)) : Buffer.concat(chunks);
    calls.push({ path: req.url!, auth: req.headers.authorization, body });
    const send = (status: number, value?: unknown) =>
      res.writeHead(status, { "content-type": "application/json" }).end(value === undefined ? "" : JSON.stringify(value));
    if (req.url === "/api/v1/agent/enroll")
      return JSON.parse(body.toString()).token === "ose_good"
        ? send(200, { id: "a1", name: "dc1", secret: "osa_secret" })
        : send(401, { code: "invalid-token" });
    if (req.headers.authorization !== "Bearer osa_secret") return send(401, {});
    if (req.url === "/api/v1/agent/work") return send(200, { jobs: jobs.splice(0) });
    if (req.url!.endsWith("/sarif")) return send(200, { scanId: "s1" });
    if (req.url!.endsWith("/failed")) return send(204);
    send(404, {});
  });
  let base: string;
  beforeAll(async () => {
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise((r) => server.close(r)));

  it("enrols once, keeps its secret sealed, and sends back each scan or why it failed", async () => {
    const keyring = createKeyring(Buffer.alloc(32, 7));
    const statePath = join(tmp("state"), "agent.state");
    const make = (enrollToken?: string) =>
      createAgent({ url: base, version: "0.5.0", state: loadState(statePath, keyring), statePath, keyring, enrollToken, scan: options() });

    const none = make();
    expect(await none.round()).toBe(false);
    expect(none.status).toMatchObject({ enrolled: false, lastError: expect.stringMatching(/SAST_ENROLL_TOKEN/) });
    const wrong = make("ose_bad");
    await wrong.round();
    expect(wrong.status.enrolled).toBe(false);

    const agent = make("ose_good");
    jobs = [job(), job({ id: "0b8c2d1e-0000-4000-8000-000000000002", cloneUrl: `file://${repo.dir}-missing` })];
    expect(await agent.round()).toBe(true);
    expect(agent.status).toMatchObject({ enrolled: true, sastOk: true, scans: 2, scanFailures: 1, running: 0 });
    expect(readFileSync(statePath, "utf8")).not.toContain("osa_secret");
    const sarif = calls.find((c) => c.path.endsWith("/sarif"))!;
    expect(sarif.path).toBe("/api/v1/agent/jobs/0b8c2d1e-0000-4000-8000-000000000001/sarif");
    expect(JSON.parse(sarif.body.toString()).runs[0].results).toHaveLength(2);
    const failed = calls.find((c) => c.path.endsWith("/failed"))!;
    expect(JSON.parse(failed.body.toString()).error).toMatch(/^Cloning acme\/web failed/);

    // Started again, it uses the sealed secret and does not enrol a second time.
    calls.length = 0;
    expect(await make("ose_good").round()).toBe(false);
    expect(calls.map((c) => c.path)).toEqual(["/api/v1/agent/work"]);
  });
});
