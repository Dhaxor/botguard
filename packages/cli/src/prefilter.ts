/** Cheap pre-filter so the hook adds ~no latency to the commands that install nothing. */
export const MAYBE_INSTALL =
  /\b(?:npm|pnpm|yarn|bun|npx|pnpx|bunx|pip\d?(?:\.\d+)?|python\d?(?:\.\d+)?|py|uv|uvx|pipx|poetry|pdm|rye|hatch|git|gh|curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b/i;

export const GUARDED_TOOLS = new Set(["Bash", "PowerShell"]);

/** The command string if this hook payload is worth a full check, otherwise null. */
export function commandToCheck(raw: string): string | null {
  try {
    const input = JSON.parse(raw) as { tool_name?: string; tool_input?: { command?: unknown } };
    if (!input.tool_name || !GUARDED_TOOLS.has(input.tool_name)) return null;
    const command = input.tool_input?.command;
    return typeof command === "string" && MAYBE_INSTALL.test(command) ? command : null;
  } catch {
    return null;
  }
}
