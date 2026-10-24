// The loop: ask sast for a job, scan it, send what was found. sast being down never stops the agent; it says so in
// /readyz and keeps asking (ADR 0036, the pattern of infra-agent).
import { enroll, sendFailure, sendSarif, work, type SastError } from "./client.ts";
import { runJob, type Outcome, type ScanOptions } from "./jobs.ts";
import type { Keyring } from "./kek.ts";
import { log } from "./log.ts";
import { saveState, type AgentState } from "./state.ts";

export interface AgentOptions {
  url: string;
  version: string;
  state: AgentState;
  statePath: string;
  keyring: Keyring;
  enrollToken?: string;
  scan: ScanOptions;
  /** Tests replace the scan. */
  runJob?: (raw: unknown, o: ScanOptions) => Promise<Outcome>;
}

export interface Status {
  enrolled: boolean;
  sastOk: boolean;
  lastError: string | null;
  lastContactAt: string | null;
  scans: number;
  scanFailures: number;
  running: number;
}

export function createAgent(o: AgentOptions) {
  const status: Status = { enrolled: !!o.state.secret, sastOk: false, lastError: null, lastContactAt: null, scans: 0, scanFailures: 0, running: 0 };
  const scan = o.runJob ?? runJob;
  const failed = (err: unknown) => {
    status.sastOk = false;
    status.lastError = (err as Error).message;
    log("warn", "sast call failed", { status: (err as SastError).status, error: status.lastError });
  };

  /** Enrols once with the one-time token; afterwards the agent has its own secret. */
  async function ensureEnrolled(): Promise<boolean> {
    if (o.state.secret) return true;
    if (!o.enrollToken) {
      status.lastError = "Not enrolled: add this agent in SAST under GitHub, Agents, and start it with SAST_ENROLL_TOKEN";
      return false;
    }
    try {
      const r = await enroll(o.url, o.enrollToken, o.version);
      o.state.agentId = r.id;
      o.state.secret = r.secret;
      saveState(o.statePath, o.keyring, o.state);
      status.enrolled = true;
      log("info", "enrolled", { agentId: r.id, name: r.name });
      return true;
    } catch (err) {
      failed(err);
      return false;
    }
  }

  /** One round: ask for work and run what came, one scan at a time. Returns whether there was a job. */
  async function round(): Promise<boolean> {
    if (!(await ensureEnrolled())) return false;
    let jobs: unknown[];
    try {
      jobs = (await work(o.url, o.state.secret!, o.version)).jobs;
      status.sastOk = true;
      status.lastError = null;
      status.lastContactAt = new Date().toISOString();
    } catch (err) {
      failed(err);
      return false;
    }
    for (const job of jobs) {
      status.running++;
      try {
        const started = Date.now();
        const out = await scan(job, o.scan);
        status.scans++;
        const fields = { job: out.jobId, repository: (job as { repository?: unknown }).repository, seconds: Math.round((Date.now() - started) / 1000) };
        if (out.ok) {
          log("info", "scanned", { ...fields, findings: out.findings });
          await sendSarif(o.url, o.state.secret!, out.jobId, out.sarif).catch(failed);
        } else {
          status.scanFailures++;
          log("warn", "scan failed", { ...fields, error: out.error });
          if (out.jobId) await sendFailure(o.url, o.state.secret!, out.jobId, out.error).catch(failed);
        }
      } finally {
        status.running--;
      }
    }
    return jobs.length > 0;
  }

  return { round, status };
}
