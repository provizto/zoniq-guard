// apps/api/test-arbitrum.js

async function testArbitrumAudit() {
  const payload = {
    chain: "arbitrum",
    filename: "CommerceGateway.sol",
    code: `pragma solidity ^0.8.20;

contract CommerceGateway {
    mapping(address => uint256) public balances;

    // Critical function without onlyOwner
    function withdrawAdminFees() external {
        (bool sent, ) = msg.sender.call{value: 1 ether}("");
        require(sent, "Transfer failed");
    }

    function getTimestamp() external view returns (uint256) {
        return block.timestamp;
    }
}`
  };

  try {
    const response = await fetch("http://localhost:4000/api/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await response.json();
    console.log("\n=== HASIL AUDIT ARBITRUM DARI API ===");
    console.log(JSON.stringify(data, null, 2));
  } catch (error) {
    console.error("Gagal terhubung ke server:", error.message);
  }
}

testArbitrumAudit();