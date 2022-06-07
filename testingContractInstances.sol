// SPDX-License-Identifier:MIT

pragma solidity ^0.8.4;

contract stack{
    address public creator;
    address[] public participants;
    function setVal()public{
        creator=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
    }
    function getCreator()public view returns(address){
       return creator;
    }
}

contract simpleStacking{
   mapping(uint=> stack) public stacks;

   function create()public returns(address){
    stack temp=new stack();
    temp.setVal();
    stacks[1]=temp;
   }
   function getCreator()public view returns(address){
       return stacks[1].getCreator();
   }
}
