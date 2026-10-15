import { gunzipSync, unzipSync } from "fflate";
import type { SourceFile } from "../types";

export interface ArchiveEntry {
  path: string;
  size: number;
  /** Present for text files we decided to scan. */
  text?: string;
  /** True for executables/binaries worth reporting (exe, dll, node addons...). */
  binary?: boolean;
}

export interface ExtractLimits {
  maxFileBytes: number;
  maxTotalBytes: number;
  maxFiles: number;
}

export const DEFAULT_LIMITS: ExtractLimits = {
  maxFileBytes: 3 * 1024 * 1024,
  maxTotalBytes: 80 * 1024 * 1024,
  maxFiles: 8000,
};

const TEXT_EXT =
  /\.(m?[jt]sx?|c[jt]s|json|py|pyw|pth|pyi|sh|bash|zsh|ps1|psm1|bat|cmd|sol|vy|md|markdown|txt|rst|html?|ya?ml|toml|cfg|ini|env|example|sample|vbs|applescript|rb|go|rs|java|php|lua|pl)$/i;
const TEXT_NAMES = /(^|\/)(Makefile|Dockerfile|Procfile|setup|install|README|LICENSE|\.npmrc|\.pypirc|requirements[^/]*)$/i;
const BINARY_EXT = /\.(exe|dll|scr|msi|com|jar|apk|dmg|pkg|app|so|dylib|node|bin|elf|deb|rpm)$/i;
const SKIP_DIRS = /(^|\/)(\.git|node_modules|__pycache__|\.venv|venv|\.tox|\.mypy_cache|\.pytest_cache|\.next|coverage)\//;

export function isScannablePath(path: string): boolean {
  return !SKIP_DIRS.test(path) && (TEXT_EXT.test(path) || TEXT_NAMES.test(path));
}

export function isBinaryPath(path: string): boolean {
  return BINARY_EXT.test(path);
}

export function decodeText(bytes: Uint8Array): string | undefined {
  const head = bytes.subarray(0, 8192);
  let control = 0;
  for (const b of head) {
    if (b === 0) return undefined;
    if (b < 9 || (b > 13 && b < 32)) control++;
  }
  if (head.length && control / head.length > 0.1) return undefined;
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

function readString(buf: Uint8Array, start: number, len: number): string {
  let end = start;
  while (end < start + len && buf[end] !== 0) end++;
  return new TextDecoder().decode(buf.subarray(start, end));
}

function readOctal(buf: Uint8Array, start: number, len: number): number {
  // GNU base-256 encoding for huge sizes: high bit set.
  if ((buf[start]! & 0x80) !== 0) {
    let n = 0;
    for (let i = start + 1; i < start + len; i++) n = n * 256 + buf[i]!;
    return n;
  }
  const s = readString(buf, start, len).trim();
  return s ? parseInt(s, 8) : 0;
}

function parsePax(data: Uint8Array): Record<string, string> {
  const out: Record<string, string> = {};
  const text = new TextDecoder().decode(data);
  let i = 0;
  while (i < text.length) {
    const space = text.indexOf(" ", i);
    if (space < 0) break;
    const len = parseInt(text.slice(i, space), 10);
    if (!len) break;
    const record = text.slice(space + 1, i + len - 1);
    const eq = record.indexOf("=");
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    i += len;
  }
  return out;
}

/** Strip the single wrapper directory archives use ("package/", "owner-repo-sha/", "name-1.0/"). */
function stripWrapper(entries: ArchiveEntry[]): ArchiveEntry[] {
  const firstSegments = new Set(entries.map((e) => e.path.split("/")[0]));
  if (firstSegments.size !== 1 || entries.every((e) => !e.path.includes("/"))) return entries;
  return entries.map((e) => ({ ...e, path: e.path.slice(e.path.indexOf("/") + 1) })).filter((e) => e.path);
}

export function extractTarGz(gz: Uint8Array, limits: ExtractLimits = DEFAULT_LIMITS): ArchiveEntry[] {
  return extractTar(gunzipSync(gz), limits);
}

export function extractTar(tar: Uint8Array, limits: ExtractLimits = DEFAULT_LIMITS): ArchiveEntry[] {
  const entries: ArchiveEntry[] = [];
  let offset = 0;
  let total = 0;
  let longName: string | undefined;
  let pax: Record<string, string> = {};
  while (offset + 512 <= tar.length && entries.length < limits.maxFiles) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break;
    const name = readString(header, 0, 100);
    const size = readOctal(header, 124, 12);
    const type = String.fromCharCode(header[156] || 48);
    const prefix = readString(header, 345, 155);
    const dataStart = offset + 512;
    const data = tar.subarray(dataStart, dataStart + size);
    offset = dataStart + Math.ceil(size / 512) * 512;

    if (type === "L") {
      longName = readString(data, 0, data.length);
      continue;
    }
    if (type === "x") {
      pax = parsePax(data);
      continue;
    }
    if (type === "g") continue;
    const path = (pax.path ?? longName ?? (prefix ? `${prefix}/${name}` : name)).replace(/^\.\//, "");
    longName = undefined;
    pax = {};
    if (type !== "0" && type !== "\0" && type !== "7") continue; // dirs, links, devices

    const entry: ArchiveEntry = { path, size };
    if (isBinaryPath(path)) entry.binary = true;
    else if (isScannablePath(path) && size <= limits.maxFileBytes && total + size <= limits.maxTotalBytes) {
      const text = decodeText(data);
      if (text !== undefined) {
        entry.text = text;
        total += size;
      }
    }
    entries.push(entry);
  }
  return stripWrapper(entries);
}

export function extractZip(zip: Uint8Array, limits: ExtractLimits = DEFAULT_LIMITS): ArchiveEntry[] {
  const entries: ArchiveEntry[] = [];
  let total = 0;
  const files = unzipSync(zip, {
    filter: (f) => {
      const keep = isScannablePath(f.name) && f.originalSize <= limits.maxFileBytes && total + f.originalSize <= limits.maxTotalBytes;
      if (keep) total += f.originalSize;
      else if (!f.name.endsWith("/")) entries.push({ path: f.name, size: f.originalSize, binary: isBinaryPath(f.name) || undefined });
      return keep;
    },
  });
  for (const [path, data] of Object.entries(files)) {
    entries.push({ path, size: data.length, text: decodeText(data) });
  }
  return entries.slice(0, limits.maxFiles);
}

export function toSourceFiles(entries: ArchiveEntry[]): SourceFile[] {
  return entries.filter((e) => e.text !== undefined).map((e) => ({ path: e.path, text: e.text!, size: e.size }));
}
