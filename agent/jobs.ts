// What sast may ask, and how the agent does it. Neither sast nor the code is trusted here (ADR 0036): every job is
// checked before anything runs, git runs without hooks, symlinks, submodules or a shell, the forge token reaches git
// only through its environment, and Opengrep parses the code without running it. The clone lives in the work folder
// (a tmpfs) for one scan and is deleted afterwards, whatever happened.
import { spawn } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { join } from "node:path";

export interface Job {
  id: string;
  repository: string;
  cloneUrl: string;
  branch: string;
  commit: string;
  token: string;
  /** Git repositories of extra rules the install added, at its own responsibility; fetched for each scan. */
  ruleSources: string[];
}

export type Outcome = { jobId: string; ok: true; sarif: Buffer; findings: number } | { jobId: string; ok: false; error: string };

export interface ScanOptions {
  /** Where clones go: a tmpfs in the container, so code never reaches a disk. */
  workDir: string;
  opengrep: string;
  rulesDir: string;
  scanTimeoutMs: number;
  cloneTimeoutMs: number;
  /** Opengrep's memory limit for one file, in MB. */
  memoryMb: number;
  /** URL schemes git may use; tests add file:. */
  schemes?: string[];
}

const ID = /^[A-Za-z0-9-]{1,64}$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._-]{1,100}$/;
// A branch git could not read as an option or a path outside refs.
const BRANCH = /^(?!-)(?!.*\.\.)[A-Za-z0-9._/-]{1,255}$/;
const COMMIT = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const RULE_FILE = /\.ya?ml$/;
const MAX_RULE_FILES = 2000;

function url(v: unknown, what: string, schemes: string[]): string {
  if (typeof v !== "string" || v.length > 2048) throw new Error(`${what} is not a URL`);
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw new Error(`${what} is not a URL`);
  }
  if (!schemes.includes(u.protocol)) throw new Error(`${what} is not an ${schemes[0]!.slice(0, -1)} URL`);
  if (u.username || u.password) throw new Error(`${what} has credentials in it`);
  return u.href;
}

/** Throws when sast sent something the agent will not do. */
export function checkJob(raw: unknown, schemes = ["https:"]): Job {
  const j = raw as Partial<Job> | null;
  if (!j || typeof j !== "object" || typeof j.id !== "string" || !ID.test(j.id)) throw new Error("a job needs an id");
  if (typeof j.repository !== "string" || !REPOSITORY.test(j.repository)) throw new Error("repository is not owner/name");
  if (typeof j.branch !== "string" || !BRANCH.test(j.branch)) throw new Error("branch is not a branch name");
  if (typeof j.commit !== "string" || !COMMIT.test(j.commit)) throw new Error("commit is not a commit hash");
  if (typeof j.token !== "string" || j.token.length > 1024 || /[\s]/.test(j.token)) throw new Error("token is not a token");
  if (!Array.isArray(j.ruleSources) || j.ruleSources.length > 10) throw new Error("rule sources are a list of at most 10 URLs");
  return {
    id: j.id,
    repository: j.repository,
    cloneUrl: url(j.cloneUrl, "cloneUrl", schemes),
    branch: j.branch,
    commit: j.commit,
    token: j.token,
    ruleSources: j.ruleSources.map((s, i) => url(s, `rule source ${i + 1}`, schemes)),
  };
}

class RunError extends Error {}

/** Runs a program without a shell, in its own process group so a time limit stops its children too. */
function run(cmd: string, args: string[], o: { cwd?: string; env: NodeJS.ProcessEnv; timeoutMs: number; what: string }): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: o.cwd, env: o.env, stdio: ["ignore", "ignore", "pipe"], detached: true });
    let stderr = "";
    child.stderr.on("data", (d: Buffer) => (stderr = (stderr + d.toString("utf8")).slice(-2000)));
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        process.kill(-child.pid!, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    }, o.timeoutMs);
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(new RunError(`${o.what} could not start: ${err.message}`));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (timedOut) return reject(new RunError(`${o.what} took longer than ${Math.round(o.timeoutMs / 60_000)} minutes`));
      if (code === 0) return resolve();
      const last = stderr.trim().split("\n").filter(Boolean).slice(-3).join(" ");
      reject(new RunError(`${o.what} failed (exit ${code})${last ? `: ${last}` : ""}`));
    });
  });
}

/** Git's settings for one call, all through its environment: nothing from a config file, no prompt, no hooks. */
export function gitEnv(home: string, schemes: string[], extra: Array<[string, string]> = []): NodeJS.ProcessEnv {
  const config: Array<[string, string]> = [
    ["core.hooksPath", "/dev/null"],
    ["core.symlinks", "false"],
    ["core.fsmonitor", "false"],
    ["submodule.recurse", "false"],
    ["credential.helper", ""],
    ["http.followRedirects", "false"],
    ["protocol.allow", "never"],
    ...schemes.map((s): [string, string] => [`protocol.${s.slice(0, -1)}.allow`, "always"]),
    ...extra,
  ];
  return {
    PATH: process.env.PATH,
    HOME: home,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
    GIT_LFS_SKIP_SMUDGE: "1",
    GIT_CONFIG_COUNT: String(config.length),
    ...Object.fromEntries(
      config.flatMap(([k, v], i) => [
        [`GIT_CONFIG_KEY_${i}`, k],
        [`GIT_CONFIG_VALUE_${i}`, v],
      ]),
    ),
  };
}

/** Rule files in a rule source: YAML with a top-level rules key, so a workflow file does not fail the scan. */
async function ruleFiles(dir: string, found: string[] = []): Promise<string[]> {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (found.length >= MAX_RULE_FILES || e.name.startsWith(".")) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) await ruleFiles(p, found);
    else if (e.isFile() && RULE_FILE.test(e.name) && (await stat(p)).size <= 1024 * 1024 && /^rules:/m.test(await readFile(p, "utf8"))) found.push(p);
  }
  return found;
}

const countResults = (sarif: Buffer) =>
  ((JSON.parse(sarif.toString("utf8")) as { runs?: Array<{ results?: unknown[] }> }).runs ?? []).reduce((n, r) => n + (r.results?.length ?? 0), 0);

/** Clones the commit, fetches the rule sources, scans and returns SARIF; never throws. */
export async function runJob(raw: unknown, o: ScanOptions): Promise<Outcome> {
  const schemes = o.schemes ?? ["https:"];
  let job: Job;
  try {
    job = checkJob(raw, schemes);
  } catch (err) {
    return { jobId: String((raw as { id?: unknown } | null)?.id ?? ""), ok: false, error: `The agent refused the job: ${(err as Error).message}` };
  }
  const dir = await mkdtemp(join(o.workDir, "scan-"));
  // The token never appears in an argument, a URL or a log line; an error from git is scrubbed of it all the same.
  const scrub = (s: string) => (job.token ? s.split(job.token).join("***") : s);
  try {
    const src = join(dir, "src");
    const auth: Array<[string, string]> = job.token
      ? [["http.extraHeader", `Authorization: Basic ${Buffer.from(`x-access-token:${job.token}`).toString("base64")}`]]
      : [];
    const git = (args: string[], what: string, extra = auth) =>
      run("git", args, { cwd: dir, env: gitEnv(dir, schemes, extra), timeoutMs: o.cloneTimeoutMs, what });
    await git(["init", "--quiet", src], "git init", []);
    // Exactly the commit sast queued, not whatever the branch points to by now.
    await git(["-C", src, "fetch", "--quiet", "--depth=1", "--no-tags", "--no-recurse-submodules", job.cloneUrl, job.commit], `Cloning ${job.repository}`);
    await git(["-C", src, "-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", "FETCH_HEAD"], "git checkout", []);

    const configs = [o.rulesDir];
    for (const [i, source] of job.ruleSources.entries()) {
      const into = join(dir, `rules-${i}`);
      // Rule sources are public repositories: the forge token is not sent to them.
      await git(["clone", "--quiet", "--depth=1", "--no-tags", "--no-recurse-submodules", source, into], `Fetching rule source ${source}`, []);
      configs.push(...(await ruleFiles(into)));
    }

    const out = join(dir, "out.sarif");
    await run(
      o.opengrep,
      [
        "scan",
        "--no-rewrite-rule-ids",
        ...configs.flatMap((c) => ["--config", c]),
        `--sarif-output=${out}`,
        "--timeout=30",
        `--max-memory=${o.memoryMb}`,
        "--max-target-bytes=1000000",
        "--disable-version-check",
        "--quiet",
        ".",
      ],
      { cwd: src, env: { PATH: process.env.PATH, HOME: dir }, timeoutMs: o.scanTimeoutMs, what: "Opengrep" },
    );
    const sarif = await readFile(out);
    return { jobId: job.id, ok: true, sarif, findings: countResults(sarif) };
  } catch (err) {
    return { jobId: job.id, ok: false, error: scrub(err instanceof Error ? err.message : String(err)) };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
