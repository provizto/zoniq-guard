// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommerceGateway {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No funds");

        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed");

        balances[msg.sender] = 0;
    }
}