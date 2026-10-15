/**
 * Crypto brands that malicious packages borrow to look official ("polymarket-bot", "hyperliquid-sdk-pro").
 * A package that uses a brand name but is not published from the brand's scope, GitHub org or email
 * domain is "unofficial" - not automatically bad, but a strong multiplier for other signals.
 */
export interface Brand {
  key: string;
  label: string;
  pattern: RegExp;
  npmScopes: string[];
  githubOrgs: string[];
  emailDomains: string[];
}

export const BRANDS: Brand[] = [
  { key: "polymarket", label: "Polymarket", pattern: /poly[-_.]?market/i, npmScopes: ["@polymarket"], githubOrgs: ["polymarket"], emailDomains: ["polymarket.com"] },
  { key: "kalshi", label: "Kalshi", pattern: /kalshi/i, npmScopes: ["@kalshi"], githubOrgs: ["kalshi"], emailDomains: ["kalshi.com"] },
  { key: "hyperliquid", label: "Hyperliquid", pattern: /hyper[-_.]?liquid/i, npmScopes: ["@hyperliquid"], githubOrgs: ["hyperliquid-dex"], emailDomains: ["hyperliquid.xyz"] },
  { key: "uniswap", label: "Uniswap", pattern: /uniswap/i, npmScopes: ["@uniswap"], githubOrgs: ["uniswap"], emailDomains: ["uniswap.org"] },
  { key: "metamask", label: "MetaMask", pattern: /meta[-_.]?mask/i, npmScopes: ["@metamask"], githubOrgs: ["metamask"], emailDomains: ["consensys.net", "metamask.io"] },
  { key: "phantom", label: "Phantom", pattern: /phantom[-_.]?(wallet|app|sdk|connect)/i, npmScopes: ["@phantom"], githubOrgs: ["phantom"], emailDomains: ["phantom.app"] },
  { key: "binance", label: "Binance", pattern: /binance/i, npmScopes: ["@binance"], githubOrgs: ["binance"], emailDomains: ["binance.com"] },
  { key: "coinbase", label: "Coinbase", pattern: /coinbase/i, npmScopes: ["@coinbase"], githubOrgs: ["coinbase"], emailDomains: ["coinbase.com"] },
  { key: "jupiter", label: "Jupiter", pattern: /jupiter[-_.]?(ag|swap|aggregator|exchange)|jup[-_.]?ag/i, npmScopes: ["@jup-ag"], githubOrgs: ["jup-ag"], emailDomains: ["jup.ag"] },
  { key: "raydium", label: "Raydium", pattern: /raydium/i, npmScopes: ["@raydium-io"], githubOrgs: ["raydium-io"], emailDomains: ["raydium.io"] },
  { key: "pumpfun", label: "pump.fun", pattern: /pump[-_.]?fun/i, npmScopes: ["@pump-fun"], githubOrgs: ["pump-fun"], emailDomains: ["pump.fun"] },
  { key: "axiom", label: "Axiom", pattern: /axiom[-_.]?trade/i, npmScopes: [], githubOrgs: [], emailDomains: ["axiom.trade"] },
  { key: "tg-bots", label: "a well-known trading bot", pattern: /bonk[-_.]?bot|banana[-_.]?gun|maestro[-_.]?bot|trojan[-_.]?(bot|sol)|kreo[-_.]?poly|polygun|polycop/i, npmScopes: [], githubOrgs: [], emailDomains: [] },
  { key: "anthropic", label: "Claude / Anthropic", pattern: /claude|anthropic/i, npmScopes: ["@anthropic-ai"], githubOrgs: ["anthropics"], emailDomains: ["anthropic.com"] },
];

export function matchBrands(name: string): Brand[] {
  return BRANDS.filter((b) => b.pattern.test(name));
}

export interface PublisherHints {
  /** npm scope including "@" if the package is scoped. */
  scope?: string;
  repositoryUrl?: string;
  homepage?: string;
  emails?: string[];
}

function githubOrgOf(url?: string): string | undefined {
  const m = url?.match(/github\.com[/:]([^/]+)\//i);
  return m?.[1]?.toLowerCase();
}

export function isOfficialPublisher(brand: Brand, hints: PublisherHints): boolean {
  if (hints.scope && brand.npmScopes.includes(hints.scope.toLowerCase())) return true;
  const orgs = [githubOrgOf(hints.repositoryUrl), githubOrgOf(hints.homepage)].filter(Boolean) as string[];
  if (orgs.some((o) => brand.githubOrgs.includes(o))) return true;
  return (hints.emails ?? []).some((e) => brand.emailDomains.some((d) => e.toLowerCase().endsWith(`@${d}`)));
}
