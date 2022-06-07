// SPDX-License-Identifier:MIT

pragma solidity ^0.8.4;

contract calledContract {
    // Called Contract
    uint256 public num = 10;
    address public addr = address(this);

    function setNum(uint256 _num) public {
        num = _num;
    }
}

contract caller1 {
    // This Contract Will Call CalledContract's Methods Via Its Address Passed In Parameter And This Method Is Usefull When We Has TO Call Method Of Another Contract, This Method Is Useful When We Know ABI Of Contract.
    address public addr = address(this);

    function getNum(calledContract _contract) public view returns (uint256) {
        return _contract.num();
    }

    function setNum(calledContract _contract) public {
        _contract.setNum(50);
    }
}

contract caller2 {
    // This Contract Will Call CalledContract's Methods Via Its Address Passed In Parameter
    address public addr = address(this);

    function getNum(calledContract _contract) public view returns (uint256) {
        return _contract.num();
    }

    function setNum(calledContract _contract) public {
        _contract.setNum(50);
    }
}

contract ContractB {
    // This Contract Will Be Accessed Through Call And delegatedcall Fuctions.
    string public tokenName = "Boring";
    address public addr = address(this);

    function setTokenName() external {
        tokenName = "Changed";
    }
}

// Call Method Actually Calls Method Of Contract And delegatedcall Inherits (Just Example Not Actually Inherits) That Method And Change In State Variable Will Reflect on Caller Contract State Variables.
// In Delegated Call State Of Caller Chnager As Per Slot Num.
contract ContractA {
    // If We Put Any Varibale Here So delegated Call Will Not Change tokenName State Variable.
    string public tokenName = "FunToken"; // In Delegated Call Order Of Variables Sholud Same.

    function delegatedCallFunc(address _contract) external {
        (bool success, ) = _contract.delegatecall(
            abi.encodeWithSignature("setTokenName()")
        );
    }

    function simpleCallFunc(address _contract) external {
        _contract.call(abi.encodeWithSignature("setTokenName()"));
    }
}
