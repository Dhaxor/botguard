export const SITE = {
  name: "BotGuard",
  tagline: "Check the bot before it checks out your wallet",
  description:
    "Free scanner for crypto trading-bot repos, npm/PyPI packages and Solidity contracts. Finds wallet drainers, key stealers, typosquats and fake-star repos, and runs contracts in a sandbox EVM to see where your money goes.",
  /** Where the code and Claude Code marketplace live once published. */
  repo: process.env.NEXT_PUBLIC_BOTGUARD_REPO ?? "Dhaxor/botguard",
};
