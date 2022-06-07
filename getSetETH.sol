// SPDX-License-Identifier:MIT

pragma solidity ^0.8.4;

import "@openzeppelin/contracts/utils/escrow/Escrow.sol";

contract getSetETH {
 Escrow escrow=new Escrow();

    function depositsOf(address payee) public view returns (uint256) {
       return escrow.depositsOf(payee);
    }

    function deposit(address payee) public payable  {
      escrow.deposit{value:msg.value}(payee);
    }

    function withdraw(address payable payee) public {
        escrow.withdraw(payee);
    }
    
    function totalFunds() public view returns(uint){
        return address(escrow).balance;
    }
}