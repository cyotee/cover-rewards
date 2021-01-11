# cover-rewards

Contracts for Cover Protocol bonus tokens rewards

## Development
* run `npm install` to install all node dependencies
* run `npm hardhat compile` to compile

## Auditor envionment setup
npm install --save-dev hardhat @nomiclabs/hardhat-waffle ethereum-waffle chai @nomiclabs/hardhat-ethers ethers mocha @nomiclabs/hardhat-truffle5 @nomiclabs/hardhat-web3 web3 @openzeppelin/test-helpers hardhat-gas-reporter nyc solidity-coverage

npm install solidity-docgen buidler-source-descriptor

### Run Test With hardhat EVM (as [an independent node](https://hardhat.dev/hardhat-evm/#connecting-to-hardhat-evm-from-wallets-and-other-software))
* Run `npx hardhat node` to setup a local blockchain emulator in one terminal.
* `npx hardhat test --network localhost` run tests in a new terminal.
 **`npx hardhat node` restart required after full test run.** As the blockchain timestamp has changed.

## Deploy to Kovan Testnet
* Comment out requirement in Constructor of the Migrator
* Run `npx hardhat run scripts/deploy.js --network kovan`.
* Run `npx hardhat flatten contracts/BonusRewards.sol > flat.sol` will flatten all contracts into one
* BonusRewards
`npx hardhat verify --network kovan 0xD2c9f9323A50C3fBf8F5E3773EeE133D39227c70`