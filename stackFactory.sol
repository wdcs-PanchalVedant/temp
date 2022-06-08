// SPDX-License-Identifier:MIT

pragma solidity ^0.8.4;

contract stack {
    address mainContract;

    address creator;
    address[] invited;
    address[] participants;
    uint256 minPrice;
    address winner;
    bool isCompleted;
    uint256 startTime;
    uint256 endTime;

    mapping(address => bool) private isParticipated;

    constructor(
        address _creator,
        address[] memory _invited,
        uint256 _minPrice
    ) {
        mainContract = msg.sender;
        creator = _creator;
        invited = _invited;
        minPrice = _minPrice;
        isParticipated[_creator] = true;
        participants.push(_creator);
        startTime = block.timestamp;
    }

    fallback() external payable {}

    modifier onlyMainContract() {
        require(
            msg.sender == mainContract,
            "Only Main Contract Can Call This Method"
        );
        _;
    }

    function _isParticipated(address user)
        public
        view
        onlyMainContract
        returns (bool)
    {
        return isParticipated[user];
    }

    function _creator() public view onlyMainContract returns (address) {
        return creator;
    }

    function _minStackPrice() public view onlyMainContract returns (uint256) {
        return minPrice;
    }

    function _getData()
        public
        view
        returns (
            address,
            address[] memory,
            address[] memory,
            uint256,
            address,
            bool,
            uint256,
            uint256
        )
    {
        return (
            creator,
            invited,
            participants,
            minPrice,
            winner,
            isCompleted,
            startTime,
            endTime
        );
    }

    function isInvited(address _participant) internal view returns (bool) {
        address[] memory _invited = invited;
        uint256 totalParticipants = _invited.length;
        for (uint256 i; i < totalParticipants; ) {
            if (_invited[i] == _participant) {
                return true;
            }
            unchecked {
                i++;
            }
        }
        return false;
    }

    function joinStack(address _participant) public payable onlyMainContract {
        require(
            !(isParticipated[_participant]),
            "User Is Are Already Participated"
        );
        require(isInvited(_participant), "User Is Not Invited");
        require(msg.value >= minPrice, "Price Should Greater Than Min Price");
        isParticipated[_participant] = true;
        participants.push(_participant);
    }

    function endStack(address _creator) public onlyMainContract {
        require(!(isCompleted), "Stack Is Completed");
        require(creator == _creator, "Only Creator Can Access This Method");
        uint256 randomNumber = uint256(
            keccak256(abi.encodePacked(block.difficulty, block.timestamp))
        ) % participants.length;
        isCompleted = true;
        endTime = block.timestamp;
        address winnerAddress = participants[randomNumber];
        winner = winnerAddress;
        payable(winnerAddress).transfer(address(this).balance);
    }
}

contract simpleStacking {
    event MinStackValueChanged(uint256 indexed value, uint256 time);

    address manager;
    mapping(address => stack) public stacks;
    uint256 minStackValue;

    constructor() {
        manager = msg.sender;
    }

    function isStackExists(address _stackAddress) internal view returns (bool) {
        return address(stacks[_stackAddress]) != address(0x0);
    }

    function setMinStackValue(uint256 newStackValue) public {
        minStackValue = newStackValue;
        emit MinStackValueChanged(newStackValue, block.timestamp);
    }

    function createStack(address[] memory _invited)
        public
        payable
        returns (address)
    {
        address _creator = msg.sender;
        uint256 _stackAmount = msg.value;
        require(
            _stackAmount >= minStackValue,
            "Stack Value Should Greater Than Min Value"
        );
        stack temp = new stack(_creator, _invited, _stackAmount);
        address stackAddress = address(temp);
        stacks[stackAddress] = temp;
        payable(stackAddress).transfer(msg.value);
        return stackAddress;
    }

    function joinStack(address stackAddress) public payable {
        require(isStackExists(stackAddress), "Stack Not Exists");
        stack _stack = stacks[stackAddress];
        address _participant = msg.sender;
        uint256 _stackAmount = msg.value;
        _stack.joinStack{value: _stackAmount}(_participant);
    }

    function endStack(address stackAddress) public {
        require(isStackExists(stackAddress), "Stack Not Exists");
        stacks[stackAddress].endStack(msg.sender);
    }

    function totalFunds(address stackAddress) public view returns (uint256) {
        return stackAddress.balance;
    }

    function getCreator(address stackAddress) public view returns (address) {
        return stacks[stackAddress]._creator();
    }

    function _minStackPrice(address stackAddress)
        public
        view
        returns (uint256)
    {
        return stacks[stackAddress]._minStackPrice();
    }

    function _getData(address stackAddress)
        public
        view
        returns (
            address,
            address[] memory,
            address[] memory,
            uint256,
            address,
            bool,
            uint256,
            uint256
        )
    {
        return stacks[stackAddress]._getData();
    }
}
