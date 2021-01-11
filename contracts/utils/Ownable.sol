/* @audit-standard AUDITDAO
 * @auditor cyotee
 * @auditor-wallet 0xf28dCDF515E69da11EBd264163b09b1b30DC9dC8
 * audit-result 
 */
 /* @advisory Not likely to comply with original software license **not legl advice**
  * @summary Code is reused from OpenZeppelin software library.
  * The changes made are not likely signifigant enough to qualify
  * as reimplmentation. The original MIT license requires a license
  * and copyright notice.
  * @resoltion Auditor change license statement to match original license.
  */
// SPDX-License-Identifier: MIT

/* @warning Uses a floating pragma declaration.
 * @summary While not a known vulnerability, using a floating pragma statement
 * introduces the chance that a compiler version incompatibility with the
 * implementation could introduce a vulnerability.
 * @resolution Auditor changed to static pragma statement
 */
pragma solidity 0.8.0;

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 * @author crypto-pumpkin@github
 *
 * By initialization, the owner account will be the one that called initializeOwner. This
 * can later be changed with {transferOwnership}.
 */
contract Ownable {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev COVER: Initializes the contract setting the deployer as the initial owner.
     */
    constructor () {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(_owner == msg.sender, "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}