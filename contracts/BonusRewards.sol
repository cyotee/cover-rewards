/* @audit-standard AUDITDAO
 * @auditor cyotee
 * @auditor-wallet 0xf28dCDF515E69da11EBd264163b09b1b30DC9dC8
 * audit-result 
 */
/*
 * @advisory Should have clearly defined software license.
 * Available identifiers are available at https://spdx.org/licenses/
 */
// SPDX-License-Identifier: NONE

/* @warning Uses a floating pragma declaration.
 * @summary While not a known vulnerability, using a floating pragma statement
 * introduces the chance that a compiler version incompatibility with the
 * implementation could introduce a vulnerability.
 * @resolution Auditor changed to static pragma statement
 */
pragma solidity 0.8.0;

import "./utils/Ownable.sol";
import "./utils/ReentrancyGuard.sol";
import "./utils/SafeERC20.sol";
import "./interfaces/IBonusRewards.sol";

/**
 * @title Cover Protocol Bonus Token Rewards contract
 * @author crypto-pumpkin
 * @notice ETH is not allowed to be an bonus token, use wETH instead
 */
contract BonusRewards is IBonusRewards, Ownable, ReentrancyGuard {
  using SafeERC20 for IERC20;

  uint256 private constant WEEK = 7 days;
  uint256 private constant CAL_MULTIPLIER = 1e12; // help calculate rewards/bonus PerToken only. 1e12 will allow meaningful $1 deposit in a $1bn pool
  bool public paused;
  address[] private responders;
  address[] private poolList;
  // lpToken => Pool
  mapping(address => Pool) private pools;
  // lpToken => User address => User data
  mapping(address => mapping(address => User)) private users;
  // bonus token => [] allowed authorizers to add bonus tokens
  mapping(address => address[]) private allowedTokenAuthorizers;
  // bonusTokenAddr => 1, used to avoid collecting bonus token when not ready
  mapping(address => uint8) private bonusTokenAddrMap;

  /*
   * @safe State check modifier does not change state.
   * @summary Code that checks state are generally safe.
   */
  modifier notPaused() {
    require(!paused, "BonusRewards: paused");
    _;
  }

  /*
   * @safe View functions can not change state.
   * @summary the "view" function property prevents modification of state.
   * @safe No calculation made.
   * @summary Functions to do not make calculations and simply provide state data are generally safe.
   */
  function getPoolList() external view override returns (address[] memory) {
    return poolList;
  }

  /*
   * @safe View functions can not change state.
   * @summary the "view" function property prevents modification of state.
   * @safe No calculation made.
   * @summary Functions to do not make calculations and simply provide state data are generally safe.
   */
  function getPool(address _lpToken) external view override returns (Pool memory) {
    return pools[_lpToken];
  }

  /*
   * @safe View functions can not change state.
   * @summary the "view" function property prevents modification of state.
   */
  function viewRewards(address _lpToken, address _user) public view override returns (uint256[] memory) {
    Pool memory pool = pools[_lpToken];
    User memory user = users[_lpToken][_user];
    uint256[] memory rewards = new uint256[](pool.bonuses.length);
    if (user.amount <= 0) return rewards;

    uint256 rewardsWriteoffsLen = user.rewardsWriteoffs.length;
    for (uint256 i = 0; i < rewards.length; i ++) {
      Bonus memory bonus = pool.bonuses[i];
      if (bonus.startTime < block.timestamp && bonus.remBonus > 0) {
        uint256 lpTotal = IERC20(_lpToken).balanceOf(address(this));
        uint256 bonusForTime = _calRewardsForTime(bonus, pool.lastUpdatedAt);
        uint256 bonusPerToken = bonus.accRewardsPerToken + bonusForTime / lpTotal;
        uint256 rewardsWriteoff = rewardsWriteoffsLen <= i ? 0 : user.rewardsWriteoffs[i];
        rewards[i] = user.amount * bonusPerToken / CAL_MULTIPLIER - rewardsWriteoff;
      }
    }
    return rewards;
  }

  /*
   * @safe View functions can not change state.
   * @summary the "view" function property prevents modification of state.
   * @safe No calculation made.
   * @summary Functions to do not make calculations and simply provide state data are generally safe.
   */
  function getUser(address _lpToken, address _account) external view override returns (User memory, uint256[] memory) {
    return (users[_lpToken][_account], viewRewards(_lpToken, _account));
  }

  /*
   * @safe View functions can not change state.
   * @summary the "view" function property prevents modification of state.
   * @safe No calculation made.
   * @summary Functions to do not make calculations and simply provide state data are generally safe.
   */
  function getAuthorizers(address _bonusTokenAddr) external view override returns (address[] memory) {
    return allowedTokenAuthorizers[_bonusTokenAddr];
  }

  /*
   * @safe View functions can not change state.
   * @summary the "view" function property prevents modification of state.
   * @safe No calculation made.
   * @summary Functions to do not make calculations and simply provide state data are generally safe.
   */
  function getResponders() external view override returns (address[] memory) {
    return responders;
  }

  /// @notice update pool's bonus per staked token till current block timestamp
  /*
   * @advisory Unessecary extention of attack surface.
   * @summary Upon review, there seems to be no need for this function to be public.
   *  Reducing the number of public functions narrows the attack surface of potentially explotable logic.
   */
  // CONDITIONAL ASSESSMENT PENDING FUTHER REVIEW. UNLIKELY TO BE EXPLOITABLE.
  // BEST PRACTICE IS TO USE A ACL OF APPROVED ADDRESSES FOR _lpToken
  /*
   * @unsafe Conditional state not updated until conditional operation completed.
   * @summary The variable pool.lastUpdatedAt is not updated until after the operation contingent 
   *  upon pool.lastUpdatedAt is completed. Because this function is public,
   *  and not protected against reentrancy.
   * @note Exploitability is based on usage of balanceOf function on _lpToken. This function is only unsafe
   *  if a unverified address that implements a malicious balanceOf function. This is not mitigated by the conditional return
   *  due to the fact that the default value of pool.lastUpdatedAt of a Pool retrieved for an address not previously saved
   *  would be 0. Since the block.timestamp can't be equal to or less then 0 then the conditional return would always
   *  evaluate to true.
   * @resolution
   *  @primary Added ACL for approved address for _lpToken
   *  @primary Reorder logic to set new variable to pool.lastUpdatedAt, update value of pool.lastUpdatedAt
   *    to block.timestamp. The base calculation off new variable.
   *  @primary Add require statement checking ACL of addresses. EnumerableSet.AddressSet would do this.
   *  @secondary Move to internal function to limit interaction by integrating with other transactions that
   *    will control flow organically.
   */
  function updatePool(address _lpToken) public override {
    Pool storage pool = pools[_lpToken];
    if (block.timestamp <= pool.lastUpdatedAt) return;
    uint256 lpTotal = IERC20(_lpToken).balanceOf(address(this));
    if (lpTotal == 0) {
      pool.lastUpdatedAt = block.timestamp;
      return;
    }

    for (uint256 i = 0; i < pool.bonuses.length; i ++) {
      Bonus storage bonus = pool.bonuses[i];
      if (pool.lastUpdatedAt < bonus.endTime && bonus.startTime < block.timestamp) {
        uint256 bonusForTime = _calRewardsForTime(bonus, pool.lastUpdatedAt);
        bonus.accRewardsPerToken = bonus.accRewardsPerToken + bonusForTime / lpTotal;
      }
    }
    pool.lastUpdatedAt = block.timestamp;
  }

  // CONDITIONAL ASSESSMENT PENDING FUTHER REVIEW. UNLIKELY TO BE EXPLOITABLE.
  // BEST PRACTICE IS TO USE A ACL OF APPROVED ADDRESSES FOR _lpToken
  /*
   * @unsafe Conditional state not updated until conditional operation completed in internally called function.
   * @summary The variable pool.lastUpdatedAt is not updated until after the operation contingent 
   *  upon pool.lastUpdatedAt is completed. Because this function is public, 
   *  and not protected against reentrancy this could be exploited to accrue additional rewards.
   *  This exploit is unlikely as the "if (bonusSinceLastUpdate > 0)" clause should prevent this.
   * @resolution
   *  @primary Added ACL for approved address for _lpToken
   *  @primary Reorder logic to set new variable to pool.lastUpdatedAt, update value of pool.lastUpdatedAt
   *    to block.timestamp. The base calculation off new variable. 
   *  @secondary Move to internal function to limit interaction by integrating with other transactions that
   *    will control flow organically.
   */
  function claimRewards(address _lpToken) public override {
    User memory user = users[_lpToken][msg.sender];
    if (user.amount == 0) return;

    updatePool(_lpToken);
    _claimRewards(_lpToken, user);
    _updateUserWriteoffs(_lpToken);
  }

  /*
   * @safe
   * @summary While claimRewards(address) is exploitable this function executes with a strictly controlled flow.
   * Even if the same _lpTokens value is placed in the array multiple times, the looping would prevent that from
   * exploiting to accrue additional rewards.
   */
  function claimRewardsForPools(address[] calldata _lpTokens) external override {
    for (uint256 i = 0; i < _lpTokens.length; i++) {
      claimRewards(_lpTokens[i]);
    }
  }

  // CONDITIONAL ASSESSMENT PENDING FUTHER REVIEW. UNLIKELY TO BE EXPLOITABLE.
  // BEST PRACTICE IS TO USE A ACL OF APPROVED ADDRESSES FOR _lpToken
  /*
   * @unsafe Conditional state not updated until conditional operation completed in internally called function.
   * @summary The variable pool.lastUpdatedAt is not updated until after the operation contingent 
   *  upon pool.lastUpdatedAt is completed. Because this function is public, 
   *  and not protected against reentrancy this could be exploited to accrue additional rewards.
   *  The clause "require(pools[_lpToken].lastUpdatedAt > 0, "Blacksmith: pool does not exists");" does not provide
   *  and effective implicit ACL as the value lastUpdatedAt could be forced to update to a value greater then 0.
   * @resolution
   *  @primary Added ACL for approved address for _lpToken
   *  @primary Reorder logic to set new variable to pool.lastUpdatedAt, update value of pool.lastUpdatedAt
   *    to block.timestamp. The base calculation off new variable. 
   *  @secondary Move updatePool(address) to internal function to limit interaction by integrating with other transactions that
   *    will control flow organically.
   */
  function deposit(address _lpToken, uint256 _amount) external override nonReentrant notPaused {
    require(pools[_lpToken].lastUpdatedAt > 0, "Blacksmith: pool does not exists");
    require(IERC20(_lpToken).balanceOf(msg.sender) >= _amount, "Blacksmith: insufficient balance");

    updatePool(_lpToken);
    User storage user = users[_lpToken][msg.sender];
    _claimRewards(_lpToken, user);
    user.amount = user.amount + _amount;
    _updateUserWriteoffs(_lpToken);

    IERC20(_lpToken).safeTransferFrom(msg.sender, address(this), _amount);
    emit Deposit(msg.sender, _lpToken, _amount);
  }

  /// @notice withdraw up to all user deposited
  // CONDITIONAL ASSESSMENT PENDING FUTHER REVIEW. UNLIKELY TO BE EXPLOITABLE.
  // BEST PRACTICE IS TO USE A ACL OF APPROVED ADDRESSES FOR _lpToken
  // THIS COULD BE DONE WITH EITHER ENUMERABLESET.ADDRESSSET.CONTAINS(ADDRESS) OR A of mapping( address => bool ) approvedPools.
  /*
   * @unsafe Conditional state in updatePool(address) not updated until conditional operation completed in internally called function.
   * @summary The variable pool.lastUpdatedAt is not updated until after the operation contingent 
   *  upon pool.lastUpdatedAt is completed. Because this function is public, 
   *  and not protected against reentrancy this could be exploited to accrue additional rewards.
   *  The clause "require(pools[_lpToken].lastUpdatedAt > 0, "Blacksmith: pool does not exists");" does not provide
   *  and effective implicit ACL as the value lastUpdatedAt could be forced to update to a value greater then 0.
   * @resolution
   *  @primary Added ACL for approved address for _lpToken
   *  @primary Reorder logic to set new variable to pool.lastUpdatedAt, update value of pool.lastUpdatedAt
   *    to block.timestamp. The base calculation off new variable. 
   *  @secondary Move updatePool(address) to internal function to limit interaction by integrating with other transactions that
   *    will control flow organically.
   */
  function withdraw(address _lpToken, uint256 _amount) external override nonReentrant notPaused {
    updatePool(_lpToken);

    User storage user = users[_lpToken][msg.sender];
    _claimRewards(_lpToken, user);
    uint256 amount = user.amount > _amount ? _amount : user.amount;
    user.amount = user.amount - amount;
    _updateUserWriteoffs(_lpToken);

    _safeTransfer(_lpToken, amount);
    emit Withdraw(msg.sender, _lpToken, amount);
  }

  /// @notice withdraw all without rewards
  /*
   * @safe
   * @summary Simple logic that copies stored variable to temporary variable to enable setting storage variable
   *  to 0 prior to using temporary variable for transfer. This is inherent;y reentrancy resistant.
   */
  function emergencyWithdraw(address _lpToken) external override nonReentrant {
    User storage user = users[_lpToken][msg.sender];
    uint256 amount = user.amount;
    user.amount = 0;
    _safeTransfer(_lpToken, amount);
    emit Withdraw(msg.sender, _lpToken, amount);
  }

  /// @notice called by authorizers only
  /*
   * @ownerexploitable
   * @summary Only an authorized user can add a Bonus. This requires trusting the authorized users.
   *  There are not currently any design patterns that would eliminate the need for trust in this use case.
   *  A possible solution is to enforce in code that the Bonus be tied to a token listed on Cover and has 
   *  a met a deposit threshold. This would ensure if a illegitmate Bonus was added, it would need to also 
   *  offer coverage. Not a complete mitigation. but would provide some protection against malicious use,
   */
  function addBonus(
    address _lpToken,
    address _bonusTokenAddr,
    uint256 _startTime,
    uint256 _weeklyRewards,
    uint256 _transferAmount
  ) external override notPaused {
    require(_isAuthorized(msg.sender, allowedTokenAuthorizers[_bonusTokenAddr]), "BonusRewards: not authorized caller");
    require(_startTime >= block.timestamp, "BonusRewards: startTime in the past");

    // make sure the pool is in the right state (exist with no active bonus at the moment) to add new bonus tokens
    Pool memory pool = pools[_lpToken];
    require(pool.lastUpdatedAt != 0, "BonusRewards: pool does not exist");
    Bonus[] memory bonuses = pool.bonuses;
    for (uint256 i = 0; i < bonuses.length; i++) {
      if (bonuses[i].bonusTokenAddr == _bonusTokenAddr) {
        // when there is alreay a bonus program with the same bonus token, make sure the program has ended properly
        require(bonuses[i].endTime + WEEK < block.timestamp, "BonusRewards: last bonus period hasn't ended");
        require(bonuses[i].remBonus == 0, "BonusRewards: last bonus not all claimed");
      }
    }

    IERC20 bonusTokenAddr = IERC20(_bonusTokenAddr);
    uint256 balanceBefore = bonusTokenAddr.balanceOf(address(this));
    bonusTokenAddr.safeTransferFrom(msg.sender, address(this), _transferAmount);
    uint256 received = bonusTokenAddr.balanceOf(address(this)) - balanceBefore;
    // endTime is based on how much tokens transfered v.s. planned weekly rewards
    uint256 endTime = (received / _weeklyRewards) * WEEK + _startTime;

    pools[_lpToken].bonuses.push(Bonus({
      bonusTokenAddr: _bonusTokenAddr,
      startTime: _startTime,
      endTime: endTime,
      weeklyRewards: _weeklyRewards,
      accRewardsPerToken: 0,
      remBonus: received
    }));
  }

  /// @notice extend the current bonus program, the program has to be active (endTime is in the future)
  /*
   * @ownerexploitable
   * @summary Only an authorized user can add a Bonus. This requires trusting the authorized users.
   *  There are not currently any design patterns that would eliminate the need for trust in this use case.
   *  A possible solution is to enforce in code that the Bonus be tied to a token listed on Cover and has 
   *  a met a deposit threshold. This would ensure if a illegitmate Bonus was added, it would need to also 
   *  offer coverage. Not a complete mitigation. but would provide some protection against malicious use,
   */
  function extendBonus(
    address _lpToken,
    uint256 _poolBonusId,
    address _bonusTokenAddr,
    uint256 _transferAmount
  ) external override notPaused {
    require(_isAuthorized(msg.sender, allowedTokenAuthorizers[_bonusTokenAddr]), "BonusRewards: not authorized caller");

    Bonus memory bonus = pools[_lpToken].bonuses[_poolBonusId];
    require(bonus.bonusTokenAddr == _bonusTokenAddr, "BonusRewards: bonus and id dont match");
    require(bonus.endTime > block.timestamp, "BonusRewards: bonus program ended, please start a new one");

    IERC20 bonusTokenAddr = IERC20(_bonusTokenAddr);
    uint256 balanceBefore = bonusTokenAddr.balanceOf(address(this));
    bonusTokenAddr.safeTransferFrom(msg.sender, address(this), _transferAmount);
    uint256 received = bonusTokenAddr.balanceOf(address(this)) - balanceBefore;
    // endTime is based on how much tokens transfered v.s. planned weekly rewards
    uint256 endTime = (received / bonus.weeklyRewards) * WEEK + bonus.endTime;

    pools[_lpToken].bonuses[_poolBonusId].endTime = endTime;
    pools[_lpToken].bonuses[_poolBonusId].remBonus = bonus.remBonus + received;
  }

  /// @notice add pools and authorizers to add bonus tokens for pools, combine two calls into one. Only reason we add pools is when bonus tokens will be added
  /*
   * @ownerexploitable
   * @summary Only an authorized user can add a Bonus. This requires trusting the authorized users.
   *  There are not currently any design patterns that would eliminate the need for trust in this use case.
   *  A possible solution is to enforce in code that the Bonus be tied to a token listed on Cover and has 
   *  a met a deposit threshold. This would ensure if a illegitmate Bonus was added, it would need to also 
   *  offer coverage. Not a complete mitigation. but would provide some protection against malicious use.
   */
  function addPoolsAndAllowBonus(
    address[] calldata _lpTokens,
    address[] calldata _bonusTokenAddrs,
    address[] calldata _authorizers
  ) external override onlyOwner notPaused {
    // add pools
    for (uint256 i = 0; i < _lpTokens.length; i++) {
      Pool memory pool = pools[_lpTokens[i]];
      require(pool.lastUpdatedAt == 0, "BonusRewards: pool exists");
      pools[_lpTokens[i]].lastUpdatedAt = block.timestamp;
      poolList.push(_lpTokens[i]);
    }

    // add bonus tokens and their authorizers (who are allowed to add the token to pool)
    for (uint256 i = 0; i < _bonusTokenAddrs.length; i++) {
      allowedTokenAuthorizers[_bonusTokenAddrs[i]] = _authorizers;
      bonusTokenAddrMap[_bonusTokenAddrs[i]] = 1;
    }
  }

  /// @notice use start and end to avoid gas limit in one call
  /*
   * @safe
   * @summary Simple logic that copies stored variable to temporary variable to enable setting storage variable
   *  to 0 prior to using temporary variable for transfer. This is inherent;y reentrancy resistant.
   */
  function updatePools(uint256 _start, uint256 _end) external override {
    address[] memory poolListCopy = poolList;
    for (uint256 i = _start; i < _end; i++) {
      updatePool(poolListCopy[i]);
    }
  }

  /// @notice collect bonus token dust to treasury
  /*
   * @safe
   * @summary Only an authorized user can withdraw tokens. The 1 week delay on withdrawal after the end of the program period
   * prevents the owner from stealing funds during the program.
   */
  function collectDust(address _token, address _lpToken, uint256 _poolBonusId) external override onlyOwner {
    require(pools[_token].lastUpdatedAt == 0, "BonusRewards: lpToken, not allowed");

    uint256 balance = IERC20(_token).balanceOf(address(this));
    if (bonusTokenAddrMap[_token] == 1) {
      // bonus token
      Bonus memory bonus = pools[_lpToken].bonuses[_poolBonusId];
      require(bonus.bonusTokenAddr == _token, "BonusRewards: wrong pool");
      require(bonus.endTime + WEEK < block.timestamp, "BonusRewards: not ready");
      balance = bonus.remBonus;
      pools[_lpToken].bonuses[_poolBonusId].remBonus = 0;
    }

    if (_token == address(0)) { // token address(0) = ETH
      payable(owner()).transfer(address(this).balance);
    } else {
      IERC20(_token).transfer(owner(), balance);
    }
  }

  /*
   * @ownerexploitable
   * @summary Only an authorized user can add a responder. There is not currently a good design pattern to mitigate this.
   */
  function setResponders(address[] calldata _responders) external override onlyOwner {
    responders = _responders;
  }

  /*
   * @ownerexploitable
   * @summary Only an authorized user can pause rewards. There is not currently a good design pattern to mitigate this.
   */
  function setPaused(bool _paused) external override {
    require(_isAuthorized(msg.sender, responders), "BonusRewards: caller not responder");
    paused = _paused;
  }

  function _updateUserWriteoffs(address _lpToken) private {
    Bonus[] memory bonuses = pools[_lpToken].bonuses;
    User storage user = users[_lpToken][msg.sender];
    for (uint256 i = 0; i < bonuses.length; i++) {
      // update writeoff to match current acc rewards per token
      if (user.rewardsWriteoffs.length == i) {
        user.rewardsWriteoffs.push(user.amount * bonuses[i].accRewardsPerToken / CAL_MULTIPLIER);
      } else {
        user.rewardsWriteoffs[i] = user.amount * bonuses[i].accRewardsPerToken / CAL_MULTIPLIER;
      }
    }
  }

  /// @notice tranfer upto what the contract has
  /*
   * @safe
   * @summary Simple logic that ensures the last of the rewards can be collected by wrapping the SafeERC20.safeTransfer.
   */
  function _safeTransfer(address _token, uint256 _amount) private returns (uint256 _transferred) {
    IERC20 token = IERC20(_token);
    uint256 balance = token.balanceOf(address(this));
    if (balance > _amount) {
      token.safeTransfer(msg.sender, _amount);
      _transferred = _amount;
    } else if (balance > 0) {
      token.safeTransfer(msg.sender, balance);
      _transferred = balance;
    }
  }

  /*
   * @safe
   * @summary This could result in a locked contract is the checklist gets too large. This is unlikely.
   *  Could be mitigated by using a mapping for the ACL instead.
   */
  function _calRewardsForTime(Bonus memory _bonus, uint256 _lastUpdatedAt) internal view returns (uint256) {
    if (_bonus.endTime <= _lastUpdatedAt) return 0;

    uint256 calEndTime = block.timestamp > _bonus.endTime ? _bonus.endTime : block.timestamp;
    uint256 calStartTime = _lastUpdatedAt > _bonus.startTime ? _lastUpdatedAt : _bonus.startTime;
    uint256 timePassed = calEndTime - calStartTime;
    return _bonus.weeklyRewards * CAL_MULTIPLIER * timePassed / WEEK;
  }

  /*
   * @safe Logic makes consistent use of proper storage and safety functions for exeution.
   */
  function _claimRewards(address _lpToken, User memory _user) private {
    // only claim if user has deposited before
    if (_user.amount > 0) {
      uint256 rewardsWriteoffsLen = _user.rewardsWriteoffs.length;
      Bonus[] memory bonuses = pools[_lpToken].bonuses;
      for (uint256 i = 0; i < bonuses.length; i++) {
        uint256 rewardsWriteoff = rewardsWriteoffsLen == i ? 0 : _user.rewardsWriteoffs[i];
        uint256 bonusSinceLastUpdate = _user.amount * bonuses[i].accRewardsPerToken / CAL_MULTIPLIER - rewardsWriteoff;
        if (bonusSinceLastUpdate > 0) {
          uint256 transferred = _safeTransfer(bonuses[i].bonusTokenAddr, bonusSinceLastUpdate); // transfer bonus tokens to user
          pools[_lpToken].bonuses[i].remBonus = bonuses[i].remBonus - transferred;
        }
      }
    }
  }

  // only owner or authorized users from list
  /*
   * @unsafe
   * @summary This could result in a locked contract is the checklist gets too large. This is unlikely.
   *  Could be mitigated by using a mapping for the ACL instead.
   */
  function _isAuthorized(address _addr, address[] memory checkList) private view returns (bool) {
    if (_addr == owner()) return true;

    for (uint256 i = 0; i < checkList.length; i++) {
      if (msg.sender == checkList[i]) {
        return true;
      }
    }
    return false;
  }
}
