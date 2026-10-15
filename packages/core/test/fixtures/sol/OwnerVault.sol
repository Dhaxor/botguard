// SPDX-License-Identifier: MIT
// BotGuard TEST FIXTURE: a harmless vault that only pays its deployer.
pragma solidity ^0.8.20;

interface IRouter {
    function swapExactETHForTokens(uint256 amountOutMin, address[] calldata path, address to, uint256 deadline)
        external
        payable
        returns (uint256[] memory amounts);
}

contract OwnerVault {
    address public owner;
    IRouter constant router = IRouter(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    function withdraw() external {
        require(msg.sender == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }

    function buy(address token) external {
        require(msg.sender == owner, "not owner");
        address[] memory path = new address[](2);
        path[0] = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
        path[1] = token;
        router.swapExactETHForTokens{value: address(this).balance}(0, path, owner, block.timestamp);
    }
}
