/** Well-known contracts and programs a bot may legitimately send funds or approvals to. Lowercase EVM keys. */
export const KNOWN_ADDRESSES: Record<string, string> = {
  "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
  "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 SwapRouter",
  "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap SwapRouter02",
  "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
  "0x66a9893cc07d91d95644aedd05d03f95e1dba8af": "Uniswap Universal Router (v4)",
  "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b": "Uniswap Universal Router (old)",
  "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
  "0x10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap Router (BSC)",
  "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch Router v5",
  "0x111111125421ca6dc452d289314280a0f8842a65": "1inch Router v6",
  "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
  "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e": "Polymarket CTF Exchange",
  "0xc5d563a36ae78145c45a50134d48a1215220f80a": "Polymarket Neg Risk CTF Exchange",
  "0xd91e80cf2e7be2e162c6513ced06f1dd0da35296": "Polymarket Neg Risk Adapter",
  "0x4d97dcd97ec945f40cf65f87097ace5ea0476045": "Polymarket Conditional Tokens",
  "0x2791bca1f2de4661ed88a30c99a7a9449aa84174": "USDC.e (Polygon)",
  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
  JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4: "Jupiter Aggregator v6",
  "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8": "Raydium AMM v4",
  "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P": "pump.fun program",
  "11111111111111111111111111111111": "Solana System Program",
  TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA: "SPL Token Program",
};

export function labelAddress(addr: string): string | undefined {
  return KNOWN_ADDRESSES[addr] ?? KNOWN_ADDRESSES[addr.toLowerCase()];
}
