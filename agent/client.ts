// Everything the agent sends goes to the sast API, and only that way (ADR 0036): the agent accepts no requests from
// sast. It asks for work and sends results.
import { gzipSync } from "node:zlib";

export class SastError extends Error {
  readonly status: number | undefined;
  readonly code: string | undefined;
  constructor(status: number | undefined, code: string | undefined, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function call(url: string, path: string, init: { secret?: string; body: Buffer | unknown; timeoutMs?: number }): Promise<Response> {
  const raw = Buffer.isBuffer(init.body) ? init.body : Buffer.from(JSON.stringify(init.body));
  let res: Response;
  try {
    res = await fetch(new URL(path, url), {
      method: "POST",
      headers: { ...(init.secret && { authorization: `Bearer ${init.secret}` }), "content-type": "application/json", "content-encoding": "gzip" },
      body: gzipSync(raw),
      signal: AbortSignal.timeout(init.timeoutMs ?? 15_000),
    });
  } catch (err) {
    throw new SastError(undefined, "unreachable", `sast at ${url} is unreachable: ${(err as Error).message}`);
  }
  if (!res.ok) {
    const p = (await res.json().catch(() => ({}))) as { code?: string; detail?: string; title?: string };
    throw new SastError(res.status, p.code, p.detail ?? p.title ?? `${res.status}`);
  }
  return res;
}

export const enroll = async (url: string, token: string, version: string) =>
  (await (await call(url, "/api/v1/agent/enroll", { body: { token, version } })).json()) as { id: string; name: string; secret: string };
export const work = async (url: string, secret: string, version: string) =>
  (await (await call(url, "/api/v1/agent/work", { secret, body: { version } })).json()) as { jobs: unknown[] };
export const sendSarif = async (url: string, secret: string, jobId: string, sarif: Buffer) =>
  void (await call(url, `/api/v1/agent/jobs/${encodeURIComponent(jobId)}/sarif`, { secret, body: sarif, timeoutMs: 120_000 }));
export const sendFailure = async (url: string, secret: string, jobId: string, error: string) =>
  void (await call(url, `/api/v1/agent/jobs/${encodeURIComponent(jobId)}/failed`, { secret, body: { error } }));
