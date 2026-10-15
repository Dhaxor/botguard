import { labelAddress } from "../intel/known-addresses";
import type { FindingCategory, Severity } from "../types";

export type Lang = "js" | "py" | "shell" | "sol" | "text";

/**
 * Tags let rules combine: reading a key is normal for a bot, sending it to a webhook is not.
 *  secret-dump  serialises every environment variable
 *  cred-files   SSH / cloud / registry credential files
 *  dotenv-raw   reads the .env file directly (often harmless on its own)
 *  pk           reads PRIVATE_KEY / MNEMONIC / CLOB API secrets (normal for bots on its own)
 *  pk-sent      puts such a secret inside a network request
 *  harvest      browser profiles, wallet extensions/files, Telegram/Discord sessions
 *  net          any outbound network call
 *  net-notify   Telegram / Discord / Slack bot APIs (fine for alerts, popular for exfiltration)
 *  net-bad      throwaway collectors: request bins, tunnels, paste/file hosts, raw public IPs
 */
export type Tag =
  | "secret-dump"
  | "cred-files"
  | "dotenv-raw"
  | "pk"
  | "pk-sent"
  | "harvest"
  | "net"
  | "net-notify"
  | "net-bad"
  | "exec"
  | "eval"
  | "decode"
  | "obf"
  | "clipboard"
  | "addr-regex"
  | "transfer-hardcoded"
  | "sweep";

export interface Standalone {
  severity: Severity;
  category: FindingCategory;
  title: string;
  detail: string;
  advice?: string;
}

export interface Rule {
  id: string;
  langs: Lang[];
  re: RegExp;
  tags: Tag[];
  /** Minimum matches in one file before the rule counts. */
  minCount?: number;
  alone?: Standalone;
  /** Drop matches the predicate rejects (private IPs, well-known installers...). */
  accept?: (match: string) => boolean;
  /** For call-shaped matches ending in "(": only count it if the call's arguments pass. */
  argsTest?: (args: string) => boolean;
}

export interface Combo {
  id: string;
  /** Every inner list needs at least one of its tags present in the file. */
  all: Tag[][];
  severity: Severity;
  category: FindingCategory;
  title: string;
  detail: string;
  advice?: string;
}

const CODE: Lang[] = ["js", "py", "shell"];
const SECRET_NAME = String.raw`\w*(?:PRIVATE_?KEY|MNEMONIC|SEED_?PHRASE|SECRET_?KEY)\w*|CLOB_(?:API_KEY|SECRET|PASS_?PHRASE)|POLY_(?:API_KEY|SECRET|PASS_?PHRASE)`;

const WALLET_EXTENSION_IDS = [
  "nkbihfbeogaeaoehlefnkodbefgpgknn", // MetaMask
  "bfnaelmomeimhlpmgjnjophhpkkoljpa", // Phantom
  "hnfanknocfeofbddgcijnmhnfnkdnaad", // Coinbase Wallet
  "acmacodkjbdgmoleebolmdjonilkdbch", // Rabby
  "mcohilncbfahbmgdjkbpemcciiolgcge", // OKX Wallet
  "bhhhlbepdkbapadjdnnojkbgioiodbic", // Solflare
  "ibnejdfjmmkpcnlpebklmnkoeoihofec", // TronLink
  "fhbohimaelbohpjbbldcngcnapndodjp", // Binance Wallet
  "egjidjbpglichdcondbcbdnbeeppgdph", // Trust Wallet
  "aholpfdialjgjfhomihkjbmgjidlcdno", // Exodus Web3
  "dmkamcknogkgcdfhhbddcghachkejeap", // Keplr
  "ejbalbakoplchlghecdalmeeeajnimhm", // MetaMask (Edge)
];

/** Installers people legitimately pipe into a shell. */
export const TRUSTED_INSTALL_HOSTS =
  /\b(?:sh\.rustup\.rs|rustup\.rs|get\.docker\.com|deb\.nodesource\.com|rpm\.nodesource\.com|raw\.githubusercontent\.com\/(?:nvm-sh|Homebrew|foundry-rs|coral-xyz|solana-labs|anza-xyz)|install\.python-poetry\.org|astral\.sh|bun\.sh|foundry\.paradigm\.xyz|release\.solana\.com|release\.anza\.xyz|deno\.land|get\.pnpm\.io|claude\.ai\/install|starship\.rs|pyenv\.run|get\.helm\.sh|ollama\.com\/install|fnm\.vercel\.app|install\.determinate\.systems|sdk\.cloud\.google\.com|awscli\.amazonaws\.com|cli\.github\.com|tailscale\.com\/install|get\.k3s\.io)/i;

function isPublicIp(url: string): boolean {
  const m = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/.exec(url);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if ([a, b, Number(m[3]), Number(m[4])].some((n) => n > 255)) return false;
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 192 && b === 168) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  // Documentation ranges (RFC 5737) and the classic placeholder.
  if ((a === 192 && b === 0 && Number(m[3]) === 2) || (a === 198 && b === 51 && Number(m[3]) === 100) || (a === 203 && b === 0 && Number(m[3]) === 113)) return false;
  if (m[0] === "1.2.3.4") return false;
  return true;
}

const SECRET_VALUE = new RegExp(
  String.raw`(?:${SECRET_NAME}|\bprivateKey\b|\bprivate_key\b|\bmnemonic\b|\bseedPhrase\b|\bseed_phrase\b)`,
  "g",
);
const SIGNING_CONTEXT = /createHmac|hmac|sign|Signature|signer|derive|keccak|sha256|encrypt/i;

/** A key mentioned inside request arguments, but not as input to a local signing/HMAC call. */
function secretSentInArgs(args: string): boolean {
  for (const m of args.matchAll(SECRET_VALUE)) {
    const before = args.slice(Math.max(0, m.index - 60), m.index);
    if (!SIGNING_CONTEXT.test(before)) return true;
  }
  return false;
}

function isUnknownRecipient(match: string): boolean {
  const addr = /0x[0-9a-fA-F]{40}|[1-9A-HJ-NP-Za-km-z]{32,44}/.exec(match)?.[0];
  return !addr || !labelAddress(addr);
}

export const RULES: Rule[] = [
  // ---- secrets -------------------------------------------------------------------------------
  {
    id: "env-dump",
    langs: ["js"],
    re: /JSON\.stringify\(\s*(?:\{\s*\.\.\.\s*)?process\.env\s*\}?\s*[,)]/g,
    tags: ["secret-dump"],
  },
  {
    id: "py-env-dump",
    langs: ["py"],
    re: /json\.dumps\(\s*(?:dict\()?\s*os\.environ\b|str\(\s*os\.environ\s*\)|dict\(\s*os\.environ\s*\)\s*\)/g,
    tags: ["secret-dump"],
  },
  {
    id: "dotenv-raw-read",
    langs: ["js"],
    re: /read(?:File|FileSync)\s*\([^)\n]{0,120}?['"`][^'"`\n]*[\\/]?\.env(?:\.local|\.production)?['"`]/g,
    tags: ["dotenv-raw"],
  },
  {
    id: "py-dotenv-raw-read",
    langs: ["py"],
    re: /open\(\s*(?:f?['"][^'"\n]*[\\/]?\.env['"]|os\.path\.join\([^)\n]*['"]\.env['"]\))/g,
    tags: ["dotenv-raw"],
  },
  {
    id: "private-key-var",
    langs: ["js", "py"],
    re: new RegExp(
      String.raw`process\.env(?:\.|\[['"])(?:${SECRET_NAME})|os\.(?:getenv|environ\.get)\(\s*['"](?:${SECRET_NAME})['"]|os\.environ\[\s*['"](?:${SECRET_NAME})['"]\s*\]`,
      "g",
    ),
    tags: ["pk"],
  },
  {
    id: "secret-in-request",
    langs: ["js", "py"],
    re: /(?:(?<![\w.])fetch|\baxios(?:\.(?:post|put|get|request))?|\bgot(?:\.post)?|\bhttps?\.request|\brequests\.(?:post|put|get)|\bhttpx\.(?:post|put|get))\s*\(/g,
    argsTest: secretSentInArgs,
    tags: ["pk-sent", "net"],
    alone: {
      severity: "high",
      category: "exfiltration",
      title: "Sends a private key or seed phrase in a network request",
      detail: "A private key, mnemonic or API secret appears inside the arguments of an HTTP call. Bots sign locally; they never need to send your key anywhere.",
      advice: "Do not run this with a real wallet. If you did, move funds to a new wallet from a clean device.",
    },
  },
  {
    id: "ssh-keys",
    langs: CODE,
    re: /\.ssh[\\/]+(?:id_\w+|authorized_keys|config)\b|['"`]id_(?:rsa|ed25519|ecdsa)['"`]/g,
    tags: ["cred-files"],
    alone: {
      severity: "medium",
      category: "secrets",
      title: "Reads SSH keys",
      detail: "The code references private SSH key files. A trading bot has no reason to touch them; stealers grab them to break into your servers and GitHub.",
    },
  },
  {
    id: "cloud-credentials",
    langs: CODE,
    re: /\.aws[\\/]+credentials|['"`/\\]\.npmrc['"`]|\.git-credentials|\.docker[\\/]+config\.json|\.kube[\\/]+config|\.config[\\/]+gcloud|['"`/\\]\.pypirc['"`]/g,
    tags: ["cred-files"],
    alone: {
      severity: "medium",
      category: "secrets",
      title: "Reads cloud or registry credentials",
      detail: "The code references credential files (AWS, npm, Docker, Kubernetes, PyPI). Malware collects these to take over accounts and publish more malware.",
    },
  },
  {
    id: "wallet-files",
    langs: CODE,
    re: /wallet\.dat\b|Electrum[\\/]+wallets|[\\/]Exodus[\\/]+exodus\.wallet|atomic[\\/]+Local Storage|Ethereum[\\/]+keystore|keystore[\\/]+UTC--/gi,
    tags: ["harvest"],
    alone: {
      severity: "high",
      category: "wallet",
      title: "Looks for desktop wallet files",
      detail: "The code references storage of desktop wallets (Bitcoin Core, Electrum, Exodus, Atomic, keystores). This is a hallmark of crypto stealers.",
    },
  },
  {
    id: "wallet-extensions",
    langs: CODE,
    re: new RegExp(`Local Extension Settings|${WALLET_EXTENSION_IDS.join("|")}`, "g"),
    tags: ["harvest"],
    alone: {
      severity: "high",
      category: "wallet",
      title: "Targets browser wallet extensions",
      detail: "The code references the storage of browser wallet extensions such as MetaMask or Phantom. No trading bot needs this; wallet stealers do.",
    },
  },
  {
    id: "browser-data",
    langs: CODE,
    re: /['"`][^'"`\n]{0,80}(?:Login Data|Local State|Web Data)['"`]|(?:Google[\\/]+Chrome|BraveSoftware|Microsoft[\\/]+Edge|Opera Software|Mozilla[\\/]+Firefox)[\\/]+(?:User Data|Profiles)|CryptUnprotectData|\bbrowser_cookie3\b|\bwin32crypt\b/g,
    tags: ["harvest"],
    alone: {
      severity: "high",
      category: "secrets",
      title: "Reads browser passwords or cookies",
      detail: "The code reaches into browser profile data (saved passwords, cookies, encryption keys). This is what info-stealers do.",
    },
  },
  {
    id: "messenger-sessions",
    langs: CODE,
    re: /Telegram Desktop[\\/]+tdata|[\\/]tdata[\\/]+|discord(?:canary|ptb)?[\\/]+Local Storage[\\/]+leveldb/gi,
    tags: ["harvest"],
    alone: {
      severity: "high",
      category: "secrets",
      title: "Steals Telegram or Discord sessions",
      detail: "The code references Telegram Desktop's tdata folder or Discord's token storage, which lets an attacker log in as you.",
    },
  },

  // ---- network ---------------------------------------------------------------------------------
  {
    id: "net",
    langs: ["js"],
    re: /(?<![\w.])fetch\s*\(|\baxios(?:\.(?:get|post|put|request|create))?\s*\(|\bhttps?\.(?:request|get)\s*\(|\bnew\s+XMLHttpRequest\b|\bgot(?:\.(?:get|post))?\s*\(|\bnet\.(?:connect|createConnection)\s*\(|\bnew\s+WebSocket\s*\(|\bundici\.(?:request|fetch)\s*\(/g,
    tags: ["net"],
  },
  {
    id: "py-net",
    langs: ["py"],
    re: /\brequests\.(?:post|put|get|request|Session)\b|\burllib\.request\.(?:urlopen|Request)\b|\bhttpx\.(?:post|put|get|AsyncClient|Client)\b|\baiohttp\.ClientSession\b|\bsocket\.socket\s*\(|\bhttp\.client\.HTTPS?Connection\b/g,
    tags: ["net"],
  },
  {
    id: "notify-endpoint",
    langs: CODE,
    re: /api\.telegram\.org\/bot|discord(?:app)?\.com\/api\/webhooks\/|hooks\.slack\.com\/services\//g,
    tags: ["net-notify", "net"],
  },
  {
    id: "collector-endpoint",
    langs: CODE,
    re: /webhook\.site|requestbin|pipedream\.net|\.oast\.(?:fun|me|pro|live|site|online)|interact\.sh|burpcollaborator|canarytokens|ngrok(?:-free)?\.(?:io|app|dev)|\.trycloudflare\.com|serveo\.net|localtunnel\.me|\bloca\.lt\b/gi,
    tags: ["net-bad", "net"],
    alone: {
      severity: "high",
      category: "exfiltration",
      title: "Talks to a throwaway collector or tunnel",
      detail: "The code contacts a request-collector or tunnelling service (webhook.site, ngrok, interactsh...). Attackers use these to receive stolen data without owning a server.",
    },
  },
  {
    id: "file-host-endpoint",
    langs: CODE,
    re: /pastebin\.com\/(?:raw|api)|paste\.ee\/|hastebin\.com|transfer\.sh|gofile\.io|\bfile\.io\b|catbox\.moe|anonfiles|pixeldrain\.com|\btemp\.sh\b|bashupload\.com|\b0x0\.st\b/gi,
    tags: ["net-bad", "net"],
    alone: {
      severity: "medium",
      category: "exfiltration",
      title: "Uses a paste or anonymous file host",
      detail: "The code reads from or uploads to an anonymous paste/file host. Malware uses these to fetch second-stage payloads or dump stolen files.",
    },
  },
  {
    id: "raw-ip-url",
    langs: CODE,
    re: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/g,
    tags: ["net-bad", "net"],
    accept: isPublicIp,
    alone: {
      severity: "medium",
      category: "exfiltration",
      title: "Connects to a hard-coded IP address",
      detail: "The code calls a server by raw public IP instead of a domain name, a common way to hide a command-and-control server.",
    },
  },
  {
    id: "dark-host",
    langs: CODE,
    re: /[a-z2-7]{16,56}\.onion\b|\.duckdns\.org|\.ddns\.net|\.no-ip\.(?:org|biz|com)/gi,
    tags: ["net-bad", "net"],
    alone: {
      severity: "medium",
      category: "exfiltration",
      title: "Uses Tor or dynamic-DNS hosts",
      detail: "Onion services and dynamic-DNS names hide who runs the server. Legitimate exchange and RPC endpoints never need them.",
    },
  },

  // ---- execution -------------------------------------------------------------------------------
  {
    id: "child-process",
    langs: ["js"],
    re: /require\(\s*['"`](?:node:)?child_process['"`]\s*\)|from\s+['"`](?:node:)?child_process['"`]/g,
    tags: ["exec"],
  },
  {
    id: "py-process",
    langs: ["py"],
    re: /\bimport\s+subprocess\b|\bfrom\s+subprocess\s+import\b|\bos\.system\s*\(|\bos\.popen\s*\(|\bpty\.spawn\s*\(/g,
    tags: ["exec"],
  },
  {
    id: "download-and-run",
    langs: CODE,
    re: /\b(?:curl|wget)\b[^\n|;&]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,200}\|\s*(?:iex|Invoke-Expression)\b|\bIEX\s*\(\s*\(?\s*New-Object\s+(?:System\.)?Net\.WebClient|\.DownloadString\s*\(|certutil(?:\.exe)?\s+-urlcache|bitsadmin(?:\.exe)?\s+\/transfer|mshta(?:\.exe)?\s+https?:|powershell(?:\.exe)?\b[^\n]{0,80}\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/gi,
    tags: ["exec", "net"],
    accept: (m) => !TRUSTED_INSTALL_HOSTS.test(m),
    alone: {
      severity: "high",
      category: "execution",
      title: "Downloads and runs a remote script",
      detail: "It pipes something from the internet straight into a shell or PowerShell. Whatever that server sends at the time runs with your permissions.",
    },
  },
  {
    id: "eval",
    langs: ["js"],
    re: /(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"`]return\s+this|\bvm\.runIn(?:New|This)?Context\s*\(|\bnew\s+vm\.Script\s*\(/g,
    tags: ["eval"],
  },
  {
    id: "py-eval",
    langs: ["py"],
    re: /(?<![\w.])(?:exec|eval)\s*\(|\b__import__\s*\(\s*['"](?:base64|zlib|marshal|codecs)['"]/g,
    tags: ["eval"],
  },
  {
    id: "py-exec-payload",
    langs: ["py"],
    re: /(?<![\w.])exec\s*\(\s*(?:base64\.\w*decode|zlib\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex|bz2\.decompress|lzma\.decompress|__import__\(\s*['"](?:base64|zlib|marshal|codecs)['"]\))/g,
    tags: ["eval", "decode"],
    alone: {
      severity: "high",
      category: "obfuscation",
      title: "Executes a hidden, encoded payload",
      detail: "It decodes a blob (base64/zlib/marshal) and runs it with exec(). This is how Python malware hides what it really does.",
    },
  },

  // ---- obfuscation -----------------------------------------------------------------------------
  {
    id: "encoded-blob",
    langs: ["js", "py"],
    re: /Buffer\.from\(\s*['"`][A-Za-z0-9+/=]{160,}['"`]\s*,\s*['"`]base64['"`]|\batob\(\s*['"`][A-Za-z0-9+/=]{160,}|['"`](?:[0-9a-fA-F]{2}){200,}['"`]|String\.fromCharCode\((?:\s*\d+\s*,){24,}|(?:\\x[0-9a-fA-F]{2}){48,}|\b(?:base64\.b64decode|zlib\.decompress|marshal\.loads)\(\s*b?['"][A-Za-z0-9+/=]{160,}/g,
    tags: ["decode"],
  },
  {
    id: "js-obfuscator",
    langs: ["js"],
    re: /\b_0x[0-9a-f]{4,6}\b/g,
    minCount: 40,
    tags: ["obf"],
    alone: {
      severity: "medium",
      category: "obfuscation",
      title: "Code is deliberately obfuscated",
      detail: "Identifiers like _0x4f2a come from a JavaScript obfuscator. Open-source bots have no reason to hide their logic; malware does.",
    },
  },
  {
    id: "pyarmor",
    langs: ["py"],
    re: /\bpyarmor_runtime\w*|__pyarmor__|\bPyArmor\b/g,
    tags: ["obf"],
    alone: {
      severity: "medium",
      category: "obfuscation",
      title: "Python code is packed with PyArmor",
      detail: "PyArmor hides the real source. Some commercial tools use it, but an obfuscated 'free bot' that handles your keys cannot be reviewed.",
    },
  },

  // ---- persistence & evasion -------------------------------------------------------------------
  {
    id: "ssh-backdoor",
    langs: CODE,
    re: /(?:appendFile(?:Sync)?|writeFile(?:Sync)?|createWriteStream|open)\s*\([^\n]{0,200}?authorized_keys|>>\s*\S*authorized_keys/g,
    tags: ["exec"],
    alone: {
      severity: "critical",
      category: "persistence",
      title: "Installs an SSH backdoor",
      detail: "It writes to authorized_keys, giving the attacker permanent remote login to your machine.",
      advice: "Treat the machine as compromised: remove unknown keys from ~/.ssh/authorized_keys and rotate every secret it held.",
    },
  },
  {
    id: "autostart",
    langs: CODE,
    re: /crontab\s+-|\/etc\/cron\.|\\CurrentVersion\\Run\b|Start Menu\\\\?Programs\\\\?Startup|schtasks(?:\.exe)?\s+\/create|launchctl\s+load|Library\/LaunchAgents|systemctl\s+(?:--user\s+)?enable/gi,
    tags: ["exec"],
    alone: {
      severity: "high",
      category: "persistence",
      title: "Makes itself start automatically",
      detail: "It registers a cron job, startup entry, scheduled task or launch agent so it keeps running after a reboot.",
    },
  },
  {
    id: "sandbox-evasion",
    langs: CODE,
    re: /\b(?:vmware|virtualbox|vboxservice|qemu-ga|sandboxie|wireshark|procmon|ollydbg|x64dbg|ida64|fiddler|httpdebugger)\b/gi,
    minCount: 3,
    tags: [],
    alone: {
      severity: "medium",
      category: "obfuscation",
      title: "Checks for analysis tools or virtual machines",
      detail: "It looks for debuggers, VMs or network sniffers, usually so it can stay quiet while a researcher is watching.",
    },
  },

  // ---- wallets ---------------------------------------------------------------------------------
  {
    id: "clipboard",
    langs: CODE,
    re: /\bclipboardy\b|navigator\.clipboard\.(?:read|write)|\bpbpaste\b|\bxclip\b|\bxsel\b|Get-Clipboard|Set-Clipboard|\bpyperclip\b|clipboard\.(?:read|write)Text/g,
    tags: ["clipboard"],
  },
  {
    id: "address-regex",
    langs: CODE,
    re: /0x\[(?:a-fA-F0-9|0-9a-fA-F|a-f0-9|0-9a-f)\]\{40\}|\[13\]\[a-km-zA-HJ-NP-Z1-9\]|bc1\[|\[1-9A-HJ-NP-Za-km-z\]\{3[2-9]/g,
    tags: ["addr-regex"],
  },
  {
    id: "hardcoded-recipient",
    langs: ["js", "py"],
    re: /\bto\s*:\s*['"`]0x[0-9a-fA-F]{40}['"`]|['"]to['"]\s*:\s*['"]0x[0-9a-fA-F]{40}['"]|\.transfer\(\s*['"`]0x[0-9a-fA-F]{40}['"`]|toPubkey\s*:\s*new\s+PublicKey\(\s*['"`][1-9A-HJ-NP-Za-km-z]{32,44}['"`]|to_pubkey\s*=\s*(?:Pubkey|PublicKey)\.from_string\(\s*['"][1-9A-HJ-NP-Za-km-z]{32,44}['"]/g,
    tags: ["transfer-hardcoded"],
    accept: isUnknownRecipient,
  },
  {
    id: "balance-sweep",
    langs: ["js", "py"],
    re: /\b(?:value|lamports)\s*[:=]\s*\w*[Bb]alance\w*\b(?:\s*-\s*\w+)?|['"]value['"]\s*:\s*\w*balance\w*/g,
    tags: ["sweep"],
  },
  {
    id: "unlimited-approval",
    langs: ["js", "py"],
    re: /approve\(\s*['"`]0x[0-9a-fA-F]{40}['"`]\s*,\s*(?:ethers\.)?(?:constants\.)?(?:MaxUint256|maxUint256|MAX_UINT256|2\s*\*\*\s*256\s*-\s*1|2n\s*\*\*\s*256n\s*-\s*1n)/g,
    tags: [],
    accept: isUnknownRecipient,
    alone: {
      severity: "medium",
      category: "wallet",
      title: "Grants an unlimited token approval to a hard-coded address",
      detail: "It lets a fixed address spend all of a token. Fine for a known DEX router, catastrophic if the address belongs to the author.",
      advice: "Look the address up on a block explorer before running this with a funded wallet.",
    },
  },
];

export const COMBOS: Combo[] = [
  {
    id: "harvest-and-send",
    all: [["harvest"], ["net", "net-bad", "net-notify"]],
    severity: "critical",
    category: "exfiltration",
    title: "Collects browser, wallet or messenger data and sends it out",
    detail: "The same file reads wallet/browser/session data and makes network requests: the core loop of an info-stealer.",
    advice: "Don't run it. If you already did, move funds to a new wallet from a clean device and rotate passwords and sessions.",
  },
  {
    id: "secrets-to-collector",
    all: [["secret-dump", "cred-files", "dotenv-raw", "pk", "pk-sent"], ["net-bad"]],
    severity: "critical",
    category: "exfiltration",
    title: "Sends secrets to a throwaway endpoint",
    detail: "It reads keys or environment secrets and talks to a collector, tunnel, paste host or raw IP in the same file.",
    advice: "Don't run it. If you did, treat every key in your .env and wallet as stolen.",
  },
  {
    id: "secret-to-chat-api",
    all: [["secret-dump", "cred-files", "pk-sent"], ["net-notify"]],
    severity: "critical",
    category: "exfiltration",
    title: "Ships secrets to a Telegram/Discord bot",
    detail: "It bulk-reads secrets (or puts a private key in a request) and calls a chat-bot API. Alerts are normal; sending your keys or environment is not.",
    advice: "Don't run it. If you did, treat every key in your .env and wallet as stolen.",
  },
  {
    id: "secrets-and-network",
    all: [["secret-dump", "cred-files"], ["net"]],
    severity: "medium",
    category: "exfiltration",
    title: "Bulk-reads secrets in code that makes network calls",
    detail: "It serialises all environment variables or touches credential files, and also sends network requests. Check where that data goes.",
  },
  {
    id: "decode-and-exec",
    all: [["decode"], ["eval"]],
    severity: "high",
    category: "obfuscation",
    title: "Decodes hidden code and executes it",
    detail: "A large encoded blob plus eval/Function/exec in one file is the classic way to smuggle a payload past reviewers.",
  },
  {
    id: "obfuscated-and-active",
    all: [["obf"], ["net", "exec", "eval"]],
    severity: "high",
    category: "obfuscation",
    title: "Obfuscated code that reaches the network or runs commands",
    detail: "Hidden logic combined with network access or process execution: you cannot verify what it sends or runs.",
  },
  {
    id: "clipboard-hijacker",
    all: [["clipboard"], ["addr-regex"]],
    severity: "high",
    category: "wallet",
    title: "Watches the clipboard for crypto addresses",
    detail: "It reads or writes the clipboard and matches wallet address patterns: the signature of a clipper that swaps the address you paste.",
  },
  {
    id: "sweep-to-hardcoded",
    all: [["transfer-hardcoded"], ["sweep"]],
    severity: "high",
    category: "wallet",
    title: "Sends your balance to a hard-coded address",
    detail: "It transfers an amount derived from your wallet balance to a fixed, unknown address written into the code.",
    advice: "Look the address up. A bot should only send funds to exchanges or routers you chose, never to the author.",
  },
];
