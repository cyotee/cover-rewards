/* @audit-standard AUDITDAO
 * @auditor cyotee
 * @auditor-wallet 0xf28dCDF515E69da11EBd264163b09b1b30DC9dC8
 * audit-result 
 */

/*
 * @advisory Should have clearly defined software license.
 *  Available identifiers are available at https://spdx.org/licenses/
 */
// SPDX-License-Identifier: NONE

/* @warning Uses a floating pragma declaration.
 * @summary While not a known vulnerability, using a floating pragma statement
 *  introduces the chance that a compiler version incompatibility with the
 *  implementation could introduce a vulnerability.
 * @resolution Auditor changed to static pragma statement
 */
pragma solidity 0.8.0;

/**
 * @title Cover Protocol Bonus Token Rewards Interface
 * @author crypto-pumpkin
 */
interface IBonusRewards {
  event Deposit(address indexed user, address indexed lpToken, uint256 amount);
  event Withdraw(address indexed user, address indexed lpToken, uint256 amount);

  /*
   * @optional
   * @advisory Should implement functions to standardize state change.
   * @summary Standardizing state change operations with functions ensures consist operations.
   */
  struct Bonus {
    address bonusTokenAddr; // the external bonus token, like CRV
    uint256 startTime;
    uint256 endTime;
    uint256 weeklyRewards; // total amount to be distributed from start to end
    uint256 accRewardsPerToken; // accumulated bonus to the lastUpdated Time
    uint256 remBonus; // remaining bonus in contract
  }

  /*
   * @optional
   * @advisory Should implement functions to standardize state change.
   * @summary Standardizing state change operations with functions ensures consist operations.
   */
  struct Pool {
    Bonus[] bonuses;
    uint256 lastUpdatedAt; // last accumulated bonus update timestamp
  }

  /*
   * @optional
   * @advisory Should implement functions to standardize state change.
   * @summary Standardizing state change operations with functions ensures consist operations.
   */
  struct User {
    uint256 amount;
    uint256[] rewardsWriteoffs; // the amount of bonus tokens to write off when calculate rewards from last update
  }

  function getPoolList() external view returns (address[] memory);
  function getResponders() external view returns (address[] memory);
  function getPool(address _lpToken) external view returns (Pool memory);
  function getUser(address _lpToken, address _account) external view returns (User memory _user, uint256[] memory _rewards);
  function getAuthorizers(address _bonusTokenAddr) external view returns (address[] memory);
  function viewRewards(address _lpToken, address _user) external view  returns (uint256[] memory);

  function updatePool(address _lpToken) external;
  function updatePools(uint256 _start, uint256 _end) external;
  function claimRewards(address _lpToken) external;
  function claimRewardsForPools(address[] calldata _lpTokens) external;
  function deposit(address _lpToken, uint256 _amount) external;
  function withdraw(address _lpToken, uint256 _amount) external;
  function emergencyWithdraw(address _lpToken) external;
  function addBonus(
    address _lpToken,
    address _bonusTokenAddr,
    uint256 _startTime,
    uint256 _weeklyRewards,
    uint256 _transferAmount
  ) external;
  function extendBonus(
    address _lpToken,
    uint256 _poolBonusId,
    address _bonusTokenAddr,
    uint256 _transferAmount
  ) external;
  // collect to owner

  // only owner
  function setResponders(address[] calldata _responders) external;
  function setPaused(bool _paused) external;
  function collectDust(address _token, address _lpToken, uint256 _poolBonusId) external;
  function addPoolsAndAllowBonus(
    address[] calldata _lpTokens,
    address[] calldata _bonusTokenAddrs,
    address[] calldata _authorizers
  ) external;
}
