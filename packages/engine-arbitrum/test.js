const { analyzeSolidityCode } = require('./src/detector');

// Contoh kode kontrak untuk diuji
const testContract = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CommerceVault {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // External call
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");

        // State update sesudah call
        balances[msg.sender] = 0;
    }

    function getBlock() external view returns (uint256) {
        return block.number;
    }
}
`;

console.log("Menjalankan analisis AST Solidity...");
const report = analyzeSolidityCode(testContract);
console.log(JSON.stringify(report, null, 2));