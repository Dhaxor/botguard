export const USER_AGENT = "botguard/0.1 (+https://github.com/Dhaxor/botguard)";

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly url: string,
    message?: string,
  ) {
    super(message ?? `HTTP ${status} for ${url}`);
    this.name = "HttpError";
  }
}

export interface RequestOptions {
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  /** Abort and throw once the body grows past this many bytes. */
  maxBytes?: number;
}

const DEFAULT_TIMEOUT = 15_000;
const DEFAULT_MAX_BYTES = 50 * 1024 * 1024;

async function request(url: string, opts: RequestOptions): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT);
  try {
    const res = await fetch(url, {
      method: opts.method ?? "GET",
      headers: { "user-agent": USER_AGENT, ...opts.headers },
      body: opts.body,
      signal: controller.signal,
      redirect: "follow",
    });
    return res;
  } catch (err) {
    if (controller.signal.aborted) throw new Error(`Timed out fetching ${url}`);
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

async function readCapped(res: Response, url: string, maxBytes: number): Promise<Uint8Array> {
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > maxBytes) throw new Error(`${url} is too large (${declared} bytes)`);
  if (!res.body) return new Uint8Array(await res.arrayBuffer());
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`${url} is too large (over ${maxBytes} bytes)`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

export async function fetchBytes(url: string, opts: RequestOptions = {}): Promise<Uint8Array> {
  const res = await request(url, opts);
  if (!res.ok) throw new HttpError(res.status, url);
  return readCapped(res, url, opts.maxBytes ?? DEFAULT_MAX_BYTES);
}

export async function fetchText(url: string, opts: RequestOptions = {}): Promise<string> {
  return new TextDecoder().decode(await fetchBytes(url, opts));
}

/** GET/POST JSON. Returns null on 404 so callers can treat "does not exist" as data. */
export async function fetchJson<T>(url: string, opts: RequestOptions = {}): Promise<T | null> {
  const res = await request(url, {
    ...opts,
    headers: { accept: "application/json", ...(opts.body ? { "content-type": "application/json" } : {}), ...opts.headers },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new HttpError(res.status, url);
  const bytes = await readCapped(res, url, opts.maxBytes ?? DEFAULT_MAX_BYTES);
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

/** Run promises with a concurrency cap, preserving order. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!, i);
    }
  });
  await Promise.all(workers);
  return out;
}
