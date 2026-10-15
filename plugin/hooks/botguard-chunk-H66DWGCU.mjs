// BotGuard Claude Code hook (generated bundle, do not edit). Source: packages/cli/src/hook.ts
// Blocks installs of known-malicious, typosquatted or impersonating npm/PyPI packages.
import { createRequire as __bgCreateRequire } from "node:module"; const require = __bgCreateRequire(import.meta.url);
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// packages/cli/src/prefilter.ts
var MAYBE_INSTALL = /\b(?:npm|pnpm|yarn|bun|npx|pnpx|bunx|pip\d?(?:\.\d+)?|python\d?(?:\.\d+)?|py|uv|uvx|pipx|poetry|pdm|rye|hatch|git|gh|curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b/i;
var GUARDED_TOOLS = /* @__PURE__ */ new Set(["Bash", "PowerShell"]);
function commandToCheck(raw) {
  try {
    const input = JSON.parse(raw);
    if (!input.tool_name || !GUARDED_TOOLS.has(input.tool_name)) return null;
    const command = input.tool_input?.command;
    return typeof command === "string" && MAYBE_INSTALL.test(command) ? command : null;
  } catch {
    return null;
  }
}

export {
  __commonJS,
  __toESM,
  MAYBE_INSTALL,
  GUARDED_TOOLS,
  commandToCheck
};
