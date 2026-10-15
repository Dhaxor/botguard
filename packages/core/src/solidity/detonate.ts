import { createEVM } from "@ethereumjs/evm";
import { createAccount, createAddressFromString, hexToBytes, type Address } from "@ethereumjs/util";
import { labelAddress } from "../intel/known-addresses";
import type { DetonationSummary, DetonationTransfer, Finding } from "../types";
import type { AbiItem, AbiParam, CompiledContract } from "./compile";

const ETHER = 10n ** 18n;
const VICTIM = "0x00000000000000000000000000000000000b0b01";
const FUNDING = 10n * ETHER;
const GAS = 30_000_000n;

/** Functions scam tutorials tell victims to call, tried first. */
const PRIORITY = ["start", "startBot", "action", "run", "execute", "withdrawal", "withdraw", "withdrawAll", "claim", "emergencyWithdraw", "stop"];

function word(hex = ""): string {
  return hex.padStart(64, "0");
}

/** Zero-ish default arguments. Dynamic values are empty; addresses are the caller. Unsupported -> null. */
function encodeDefaults(params: AbiParam[]): string | null {
  const head: string[] = [];
  const tail: string[] = [];
  const dynamicIdx: number[] = [];
  for (const p of params) {
    if (/^(uint|int)\d*$/.test(p.type) || /^bytes\d+$/.test(p.type) || p.type === "bool") head.push(word());
    else if (p.type === "address") head.push(word(VICTIM.slice(2)));
    else if (p.type === "string" || p.type === "bytes" || p.type.endsWith("[]")) {
      dynamicIdx.push(head.length);
      head.push("");
      tail.push(word()); // length 0
    } else return null; // tuples and fixed arrays: skip the function
  }
  let offset = head.length * 32;
  for (const i of dynamicIdx) {
    head[i] = word(offset.toString(16));
    offset += 32; // each dynamic value is an empty (length 0) word
  }
  return head.join("") + tail.join("");
}

function ethString(wei: bigint): string {
  const whole = wei / ETHER;
  const frac = (wei % ETHER).toString().padStart(18, "0").replace(/0+$/, "").slice(0, 4);
  return frac ? `${whole}.${frac}` : `${whole}`;
}

export interface DetonationResult extends DetonationSummary {
  findings: Finding[];
}

/**
 * Deploy each compiled contract into an empty in-memory chain as a "victim" wallet, fund it, call its
 * public functions with default arguments, and record any ETH that leaves for someone other than the
 * caller. Nothing touches a real network.
 */
export async function detonate(contracts: CompiledContract[], compilerVersion?: string): Promise<DetonationResult> {
  const summary: DetonationResult = { compiled: true, compilerVersion, contracts: [], outflows: [], findings: [] };
  let deposited = 0n;
  const victim = createAddressFromString(VICTIM);
  const deployable = contracts.filter((c) => c.bytecode && c.bytecode.length > 2).slice(0, 8);

  for (const c of deployable) {
    const evm = await createEVM();
    await evm.stateManager.putAccount(victim, createAccount({ nonce: 0n, balance: 1000n * ETHER }));
    const watched = new Set<string>();
    evm.events.on("beforeMessage", (msg) => {
      if (msg.to && msg.value > 0n) watched.add(msg.to.toString());
    });
    evm.events.on("step", (step) => {
      if (step.opcode.name === "SELFDESTRUCT") {
        const beneficiary = step.stack[step.stack.length - 1];
        if (beneficiary !== undefined) watched.add(`0x${beneficiary.toString(16).padStart(40, "0")}`);
      }
    });

    const ctor = c.abi.find((a) => a.type === "constructor");
    const ctorArgs = encodeDefaults(ctor?.inputs ?? []);
    const entry = { name: c.name, deployed: false, calls: [] as { fn: string; ok: boolean; transfers: number }[] };
    summary.contracts.push(entry);
    if (ctorArgs === null) continue;

    let deployed: Address | undefined;
    try {
      const res = await evm.runCall({
        caller: victim,
        origin: victim,
        data: hexToBytes(`0x${c.bytecode}${ctorArgs}`),
        gasLimit: GAS,
        value: 0n,
      });
      if (!res.execResult.exceptionError) deployed = res.createdAddress;
    } catch {
      /* deployment failed */
    }
    if (!deployed) continue;
    entry.deployed = true;
    const self = deployed.toString();

    const balanceOf = async (addr: string) => (await evm.stateManager.getAccount(createAddressFromString(addr)))?.balance ?? 0n;
    const snapshot = async () => {
      const m = new Map<string, bigint>();
      for (const a of watched) m.set(a, await balanceOf(a));
      return m;
    };

    const callAndTrace = async (fnLabel: string, data: Uint8Array, value: bigint) => {
      const before = await snapshot();
      let ok = false;
      try {
        const res = await evm.runCall({ caller: victim, origin: victim, to: deployed, data, value, gasLimit: GAS });
        ok = !res.execResult.exceptionError;
      } catch {
        ok = false;
      }
      if (ok) deposited += value;
      let transfers = 0;
      if (ok) {
        for (const addr of watched) {
          if (addr === VICTIM || addr === self) continue;
          const gained = (await balanceOf(addr)) - (before.get(addr) ?? 0n);
          if (gained > 0n) {
            transfers++;
            summary.outflows.push({ contract: c.name, fn: fnLabel, to: addr, valueWei: gained.toString(), label: labelAddress(addr) });
          }
        }
      }
      entry.calls.push({ fn: fnLabel, ok, transfers });
    };

    // 1) Fund it the way victims are told to: a plain transfer.
    const hasReceive = c.abi.some((a) => a.type === "receive" || (a.type === "fallback" && a.stateMutability === "payable"));
    if (hasReceive) await callAndTrace("(send ETH)", new Uint8Array(), FUNDING);

    // 2) Press every button.
    const fns = c.abi
      .filter((a) => a.type === "function" && a.stateMutability !== "view" && a.stateMutability !== "pure" && a.name)
      .sort((a, b) => {
        const pa = PRIORITY.indexOf(a.name!);
        const pb = PRIORITY.indexOf(b.name!);
        return (pa < 0 ? 99 : pa) - (pb < 0 ? 99 : pb);
      })
      .slice(0, 24);
    for (const fn of fns) {
      const sig = `${fn.name}(${(fn.inputs ?? []).map((i) => i.type).join(",")})`;
      const selector = c.methodIdentifiers[sig];
      const args = encodeDefaults(fn.inputs ?? []);
      if (!selector || args === null) continue;
      const payable = fn.stateMutability === "payable";
      // Top the contract back up so every function sees a funded contract, like a victim's would be.
      if (!payable && hasReceive && (await balanceOf(self)) === 0n) await callAndTrace("(send ETH)", new Uint8Array(), FUNDING);
      await callAndTrace(`${fn.name}()`, hexToBytes(`0x${selector}${args}`), payable ? FUNDING : 0n);
    }
  }

  summary.depositedWei = deposited.toString();
  summary.findings.push(...outflowFindings(summary.outflows, deposited));
  return summary;
}

function outflowFindings(outflows: DetonationTransfer[], deposited: bigint): Finding[] {
  const findings: Finding[] = [];
  const unknown = outflows.filter((o) => !o.label);
  const known = outflows.filter((o) => o.label);
  if (unknown.length) {
    const first = unknown[0]!;
    const recipients = [...new Set(unknown.map((o) => o.to))];
    const sends = unknown.slice(0, 3).map((o) => `${o.fn} sent ${ethString(BigInt(o.valueWei))} ETH`);
    const lost = unknown.reduce((s, o) => s + BigInt(o.valueWei), 0n);
    findings.push({
      id: "detonation.drain",
      severity: "critical",
      category: "detonation",
      title: `Running it sends your ETH to ${first.to.slice(0, 10)}…${first.to.slice(-4)}`,
      detail: `We deployed the contract in a sandbox EVM from a test wallet and used it like a victim would. Of the ${ethString(deposited)} ETH we put in, ${ethString(lost)} ETH went to ${recipients.join(", ")} (${sends.join(", ")}). That is not the wallet that deployed and funded it.`,
      advice: "This is a drainer. Do not deploy or fund it. If you already did, the ETH is gone; report the address to the platform where you found the 'bot'.",
      evidence: unknown.slice(0, 5).map((o) => ({ snippet: `${o.contract}.${o.fn} → ${o.to} (${ethString(BigInt(o.valueWei))} ETH)` })),
    });
  }
  if (known.length) {
    findings.push({
      id: "detonation.known-recipient",
      severity: "info",
      category: "detonation",
      title: `Sends ETH to ${known[0]!.label}`,
      detail: "In the sandbox the contract paid a well-known router/exchange contract, which is expected for a trading contract.",
      evidence: known.slice(0, 3).map((o) => ({ snippet: `${o.contract}.${o.fn} → ${o.label} ${o.to}` })),
    });
  }
  return findings;
}
