import type { GithubOwner, GithubReleaseAsset, GithubRepo } from "../registry/github";
import type { Finding } from "../types";

const DAY = 86_400_000;

export function daysSince(iso: string | Date | undefined, now = Date.now()): number | undefined {
  if (!iso) return undefined;
  const t = typeof iso === "string" ? Date.parse(iso) : iso.getTime();
  return Number.isNaN(t) ? undefined : Math.floor((now - t) / DAY);
}

/** Largest share of stars that landed inside any 48-hour window. */
export function starBurst(times: Date[]): number {
  if (times.length < 10) return 0;
  const t = times.map((d) => d.getTime()).sort((a, b) => a - b);
  let best = 0;
  let lo = 0;
  for (let hi = 0; hi < t.length; hi++) {
    while (t[hi]! - t[lo]! > 2 * DAY) lo++;
    best = Math.max(best, hi - lo + 1);
  }
  return best / t.length;
}

const BOT_WORDS = /\b(?:bot|mev|front[- ]?run|sniper|arbitrage|copy[- ]?trad|polymarket|kalshi|hyperliquid|pump\.?fun|drainer|wallet)\b/i;

export function repoSignals(input: {
  repo: GithubRepo;
  owner?: GithubOwner | null;
  starTimes?: Date[];
  assets?: GithubReleaseAsset[];
}): Finding[] {
  const { repo, owner } = input;
  const findings: Finding[] = [];
  const age = daysSince(repo.created_at) ?? 9999;
  const ownerAge = daysSince(owner?.created_at);
  const about = `${repo.full_name} ${repo.description ?? ""} ${(repo.topics ?? []).join(" ")}`;
  const isBotish = BOT_WORDS.test(about);
  const link = { url: repo.html_url };

  if (/\bdrainer\b/i.test(about)) {
    findings.push({
      id: "repo.drainer",
      severity: "high",
      category: "repo",
      title: "Describes itself as a drainer",
      detail: "The repository name/description mentions a drainer, i.e. a tool built to empty other people's wallets.",
      evidence: [{ ...link, snippet: repo.description ?? repo.full_name }],
    });
  }

  if (input.starTimes && repo.stargazers_count >= 20) {
    const burst = starBurst(input.starTimes);
    if (burst >= 0.6 && age < 180) {
      findings.push({
        id: "repo.star-burst",
        severity: "high",
        category: "repo",
        title: `${Math.round(burst * 100)}% of its early stars arrived within 48 hours`,
        detail: `Bought or bot-generated stars make a fresh repo look trusted. ${repo.stargazers_count} stars on a ${age}-day-old repository, mostly in one burst, fits that pattern. Malicious "Polymarket bot" repos in 2026 used exactly this trick.`,
        evidence: [link],
      });
    }
  }
  if (age < 30 && repo.stargazers_count >= 150) {
    findings.push({
      id: "repo.young-popular",
      severity: "medium",
      category: "repo",
      title: `${repo.stargazers_count} stars in ${age} days`,
      detail: "Very fast star growth on a brand-new repository is common for scam repos boosted with fake accounts.",
      evidence: [link],
    });
  }
  if (age < 14) {
    findings.push({
      id: "repo.new",
      severity: isBotish ? "low" : "info",
      category: "repo",
      title: `Repository is only ${age} day${age === 1 ? "" : "s"} old`,
      detail: "New repositories haven't had time to be reviewed or reported by others.",
      evidence: [link],
    });
  }
  if (ownerAge !== undefined && ownerAge < 30) {
    findings.push({
      id: "repo.new-owner",
      severity: "medium",
      category: "repo",
      title: `Owner account created ${ownerAge} day${ownerAge === 1 ? "" : "s"} ago`,
      detail: "Throwaway GitHub accounts are a staple of malware campaigns: when one gets banned, the next one is ready.",
      evidence: [{ url: `https://github.com/${repo.owner.login}` }],
    });
  }
  if (!repo.has_issues && isBotish) {
    findings.push({
      id: "repo.issues-disabled",
      severity: "low",
      category: "repo",
      title: "Issues are disabled",
      detail: "Victims of malicious repos usually warn others in the issues. With issues off, nobody can.",
      evidence: [link],
    });
  }
  if (repo.forks_count > repo.stargazers_count * 1.5 && repo.forks_count >= 30 && age < 90) {
    findings.push({
      id: "repo.fork-inflation",
      severity: "low",
      category: "repo",
      title: "More forks than stars on a young repo",
      detail: "Fork counts are easy to inflate with bot accounts and are often used alongside fake stars.",
      evidence: [link],
    });
  }
  const exe = (input.assets ?? []).filter((a) => /\.(exe|scr|msi|zip|rar|7z|dmg|apk)$/i.test(a.name));
  if (exe.length && isBotish) {
    findings.push({
      id: "repo.release-binaries",
      severity: "medium",
      category: "repo",
      title: "Releases ship executables or archives",
      detail: `Releases include ${exe.map((a) => a.name).slice(0, 3).join(", ")}. A downloaded bot binary can do anything; the source in the repo may not match it.`,
      evidence: [link],
    });
  }
  return findings;
}
