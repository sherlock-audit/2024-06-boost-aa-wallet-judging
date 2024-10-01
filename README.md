# Issue H-1: Unable to call some functions in the incentive contracts with onlyOwner modifier because of incorrect initialization leading to stuck funds 

Source: https://github.com/sherlock-audit/2024-06-boost-aa-wallet-judging/issues/43 

## Found by 
0xDemon, 0xNirix, 0xSecuri, 0xSolus, 0xbranded, 0xbrivan, 0xdeadbeef, 0xloscar01, Atharv, Aymen0909, Galturok, Greese, Hacek00, IvanFitro, Japy69, KupiaSec, PranavGarg, Ragnarok, SovaSlava, TessKimy, Trooper, ZanyBonzy, blutorque, ctf\_sec, dimulski, durov, frndz0ne, ge6a, haxagon, iamnmt, ke1caM, oxelmiguel, sakshamguruji, scyron6, y4y
### Summary

`BoostCore.sol` will always be set as the owner of Boost provided incentive contracts because the initializer is called here within [_makeIncentives](https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/d9f597776cc2d20fbb19ffb1f7731126cf3b6210/boost-protocol/packages/evm/contracts/BoostCore.sol#L266). Therefore any function using the onlyOwner modifier within the incentive contracts must be called by `BoostCore`. For example, there is no way to call [drawRaffle](https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/d9f597776cc2d20fbb19ffb1f7731126cf3b6210/boost-protocol/packages/evm/contracts/incentives/ERC20Incentive.sol#L137) or [clawback](https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/d9f597776cc2d20fbb19ffb1f7731126cf3b6210/boost-protocol/packages/evm/contracts/incentives/ERC20Incentive.sol#L98) from the BoostCore contract.

### Root Cause

[createBoost](https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/d9f597776cc2d20fbb19ffb1f7731126cf3b6210/boost-protocol/packages/evm/contracts/BoostCore.sol#L106) is called to create a new boost. Each incentive is initialized by the call to [_makeIncentives](https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/d9f597776cc2d20fbb19ffb1f7731126cf3b6210/boost-protocol/packages/evm/contracts/BoostCore.sol#L128). Within `_makeIncentives` the initializer is called for each incentive. The [initializer](https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/d9f597776cc2d20fbb19ffb1f7731126cf3b6210/boost-protocol/packages/evm/contracts/incentives/ERC20Incentive.sol#L36C1-L53C6) function within each incentive contract sets the owner as msg.sender which would be the `BoostCore` contract.

### Internal pre-conditions

1. Boost is created using the out of the box incentive contract as one of the incentives including: ERC20Incentive, CGDAIncentive, ERC20VariableIncentive, and ERC1155Incentive

### External pre-conditions

_No response_

### Attack Path

1. User calls `createBoost` to create a new Boost
2. They choose to use an out of the box incentive contract listed above
3. They are initialized with `BoostCore` as the owner

### Impact

- No winner can be drawn for raffle contests through ERC20Incentive contract
- Any funds in the contract that need to be rescued cannot be retrieved through [clawback](https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/78930f2ed6570f30e356b5529bd4bcbe5194eb8b/boost-protocol/packages/evm/contracts/incentives/ERC20Incentive.sol#L98)

### PoC

_No response_

### Mitigation

Owner should be specified in the init payload by the user similarly to how its done for the budget contracts [here](https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/d9f597776cc2d20fbb19ffb1f7731126cf3b6210/boost-protocol/packages/evm/contracts/budgets/SimpleBudget.sol#L54)

# Issue H-2: `incentiveId_` is not included in the hash that is signed by the validator will allow anyone to claim for a user 

Source: https://github.com/sherlock-audit/2024-06-boost-aa-wallet-judging/issues/230 

## Found by 
iamnmt, ke1caM, sakshamguruji
### Summary

`incentiveId_` is not included in the hash that is signed by the validator will allow anyone to claim for a user.

### Root Cause

`incentiveId_` is not included in the hash that is signed by the validator

https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/78930f2ed6570f30e356b5529bd4bcbe5194eb8b/boost-protocol/packages/evm/contracts/BoostCore.sol#L166

```solidity
    function claimIncentiveFor(
        uint256 boostId_,
>>      uint256 incentiveId_,
        address referrer_,
        bytes calldata data_,
        address claimant
    ) public payable nonReentrant {
        BoostLib.Boost storage boost = _boosts[boostId_];
        if (msg.value < claimFee) revert BoostError.InsufficientFunds(address(0), msg.value, claimFee);
        _routeClaimFee(boost, referrer_);

        // wake-disable-next-line reentrancy (false positive, function is nonReentrant)
>>      if (!boost.validator.validate(boostId_, incentiveId_, claimant, data_)) revert BoostError.Unauthorized();
        if (!boost.incentives[incentiveId_].claim(claimant, data_)) {
            revert BoostError.ClaimFailed(claimant, data_);
        }
    }
```

https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/78930f2ed6570f30e356b5529bd4bcbe5194eb8b/boost-protocol/packages/evm/contracts/validators/SignerValidator.sol#L61

```solidity
    function validate(uint256 boostId, uint256 incentiveId, address claimant, bytes calldata claimData)
        external
        override
        returns (bool)
    {
        if (msg.sender != _validatorCaller) revert BoostError.Unauthorized();

        (BoostClaimData memory claim) = abi.decode(claimData, (BoostClaimData));
        (SignerValidatorInputParams memory validatorData) =
            abi.decode(claim.validatorData, (SignerValidatorInputParams));

>>      bytes32 hash = hashSignerData(boostId, validatorData.incentiveQuantity, claimant, claim.incentiveData);

        if (uint256(validatorData.incentiveQuantity) <= incentiveId) {
            revert BoostError.InvalidIncentive(validatorData.incentiveQuantity, incentiveId);
        }
        if (!signers[validatorData.signer]) revert BoostError.Unauthorized();

        // Mark the incentive as claimed to prevent replays
        // checks internally if the incentive has already been claimed
        _used.setOrThrow(hash, incentiveId);

        // Return the result of the signature check
        // no need for a sig prefix since it's encoded by the EIP712 lib
        return validatorData.signer.isValidSignatureNow(hash, validatorData.signature);
    }
```

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

1. Alice calls to `claimIncentive` with 
   - `boostId_ = 0`
   - `incentiveId_ = 2`
   - `referrer_ = address(0)`
   - `data_ = 0xdeadbeef`
   - `validatorData.incentiveQuantity = 3`
2. The attacker uses the same `data_` to call to `claimIncentiveFor` with:
   - `boostId_ = 0`
   - `incentiveId_ = 1`
   - `referrer_ = address(0)`
   - `data_ = 0xdeadbeef`
   - `validatorData.incentiveQuantity = 3`
   - `claimant = address(Alice)`

Since the hash that is validated in `SignerValidator#validate` does not include `incentiveId_`, the attacker's transaction will pass this validation

https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/78930f2ed6570f30e356b5529bd4bcbe5194eb8b/boost-protocol/packages/evm/contracts/validators/SignerValidator.sol#L61

Moreover, by specifying `incentiveId_ = 1`, the check of `incentiveId` against `validatorData.incentiveQuantity` is also passed

https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/78930f2ed6570f30e356b5529bd4bcbe5194eb8b/boost-protocol/packages/evm/contracts/validators/SignerValidator.sol#L63C21-L63C52

As a result, the attacker successfully claim the incentive with `id = 1` for the user. Whereas the user intention is only claiming the incentive with `id = 2`.

### Impact

Although the incentive that is claimed by the attacker will be transferred to the user. Note that, the attacker does not steal the incentive of the user. But the attacker claims the incentive that is not expected to be claimed by the user.

This behavior will cause problem in the `CGDAIncentive` contract. For this type of incentive, the longer the user waits the more incentive the user can claim. By launching this attack, the attacker forces the user to claim early in this type of incentive, and the user can not claim again in the future. In this case, the user will lose out on the incentive, because the attacker claims early for the user.

### PoC

_No response_

### Mitigation

Include `incentiveId_` in the hash that is signed by the validator.

# Issue H-3: IncentiveBits.setOrThrow() will revert, leading to a DoS 

Source: https://github.com/sherlock-audit/2024-06-boost-aa-wallet-judging/issues/263 

## Found by 
eLSeR17, ge6a, oxelmiguel
## Summary
IncentiveBits.setOrThrow() will revert, leading to a DoS.

## Vulnerability Detail
setOrThrow() expects each incentive from 0 to 7 to be used once per hash, reverting in case that for a given hash, an already used incentive is used again. However the mechanism that checks already used incentives does not work as expected: ```alreadySet := xor(1, shr(incentive, updatedStorageValue))```, reverting if incentiveIds are not used in increasing order. 

The external call will come from BoostCore.claimIncentiveFor(), which calls SignedValidator.validate() and therefore setOrThrow(). The value of the incentiveId parameter used is arbitrary and valid as long as ```uint256(validatorData.incentiveQuantity) <= incentiveId``` is not fulfilled, which does not guarantee that calls will necessarily be in increasing order.

Example: Imagine setOrThrow() function is used with incentiveId = 5, in that case updatedStorageValue will be set to XOR (00000000, 00100000) = 00100000. Therefore, the resulting value for alreadySet is:
alreadySet = XOR (1, shr(5, 00100000)) = XOR (00000001, 00000001) = 0 => Does NOT revert.

Now setOrThrow() function is called again for incentiveId = 2, so that updatedStorageValue will be:
XOR (00100000, 00000100) = 00100100. Therefore, the new resulting value for alreadySet is:
alreadySet = XOR (1, shr(2, 00100100)) = XOR (00000001, 00001001) = 00001000 => Reverts as alreadySet != 0

## Impact
Claiming incentive for a given hash will be no longer possible, or fewer claims will be allowed depending on the last incentiveId used. This could be performed by accident by a normal user or on purpose by a malicious attacker to DoS and prevent other users from claiming from this hash.

## Code Snippet
https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/main/boost-protocol/packages/evm/contracts/validators/SignerValidator.sol#L126-L154

## Tool used
Manual Review

## Recommendation
For correctly comparing if the incentiveId index has been used, that bit must be totally isolated and XOR it with 1. For this, first shift left until we get 10000000 and then shift 7 times to right to get 1.

```solidity
function setOrThrow(IncentiveMap storage bitmap, bytes32 hash, uint256 incentive) internal {
        bytes4 invalidSelector = BoostError.IncentiveToBig.selector;
        bytes4 claimedSelector = BoostError.IncentiveClaimed.selector;
        /// @solidity memory-safe-assembly
        assembly {
            if gt(incentive, 7) {
                // if the incentive is larger the 7 (the highest bit index)
                // we revert
                mstore(0, invalidSelector)
                mstore(4, incentive)
                revert(0x00, 0x24)
            }
            mstore(0x20, bitmap.slot)
            mstore(0x00, hash)
            let storageSlot := keccak256(0x00, 0x40)
            // toggle the value that was stored inline on stack with xor
            let updatedStorageValue := xor(sload(storageSlot), shl(incentive, 1))
            // isolate the toggled bit and see if it's been unset back to zero
-           let alreadySet := xor(1, shr(incentive, updatedStorageValue))
+          let alreadySet := xor(1, shr(7, shl(incentive - 1, updatedStorageValue)))
.
.
.
```

# Issue M-1: Boost creator can collect all the fees by setting referralFee to 9_000 and give claimants his address as referrer_ address 

Source: https://github.com/sherlock-audit/2024-06-boost-aa-wallet-judging/issues/158 

## Found by 
0rpse, 0xbranded, 0xdeadbeef, 0xlookman, Atharv, Galturok, Pheonix, PranavGarg, Ragnarok, SyncCode2017, Trooper, dimulski, durov, ge6a, iamnmt, ke1caM, oxelmiguel, sakshamguruji
### Summary

The boost creator can set the value of referralFee to 9_000 when creating the boost. The `BoostCore::referralFee` (the base fee) is set to 1000 in line 70,
 
https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/main/boost-protocol/packages/evm/contracts/BoostCore.sol#L70

and added to the boost creator input in line 122, 

https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/main/boost-protocol/packages/evm/contracts/BoostCore.sol#L122

This will make the `BoostCore::referralFee` to be 10_000 (equal to the `BoostCore::FEE_DENOMINATOR`) ensuring that 100% of the fees collected when claimants claim their incentives are sent to the referrer address. To get the fees, the boost creator just need to ensure claimants use his address as referrer_ address. The protocol will never receive any fee for this particular boost.

### Root Cause

Maximum value for `BoostCore::referralFee` was not set, allowing boost creators to allocate unlimited fraction of the fees to the referrer.

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

The protocol will receive no fees as all the fees will continuously be sent to the referrer_ address.

### PoC


Please copy the code below into BoostCore.t.sol and run the test.

```solidity
    
    uint64 public constant boostAdditionalReferralFee = 9_000; // additional 90%
    uint256 public constant PRECISION = 10_000;
    uint256 public constant BASE_FEE = 1_000; // 10%
    bytes invalidCreateCalldata =
        LibZip.cdCompress(
            abi.encode(
                BoostCore.InitPayload({
                    budget: budget,
                    action: action,
                    validator: BoostLib.Target({
                        isBase: true,
                        instance: address(0),
                        parameters: ""
                    }),
                    allowList: allowList,
                    incentives: _makeIncentives(1),
                    protocolFee: 500, // 5%
                    referralFee: boostAdditionalReferralFee, // 90%
                    maxParticipants: 10_000,
                    owner: address(1)
                })
            )
        );

    function testClaimIncentive_ReferralTakesAllFees_audit() public {
        uint256 claimFee = 0.000075 ether;
        // Create a Boost first
        boostCore.createBoost(invalidCreateCalldata);

        // Mint an ERC721 token to the claimant (this contract)
        uint256 tokenId = 1;
        mockERC721.mint{value: 0.1 ether}(address(this));
        mockERC721.mint{value: 0.1 ether}(address(this));
        mockERC721.mint{value: 0.1 ether}(address(this));

        // Prepare the data payload for validation
        bytes memory data = abi.encode(address(this), abi.encode(tokenId));
        address referralAddress = makeAddr("referral");
        address protocolFeeReceiver = boostCore.protocolFeeReceiver();
        uint256 initialProtocolFeeReceiverBalance = protocolFeeReceiver.balance;
        // Claim the incentive
        boostCore.claimIncentive{value: claimFee}(0, 0, referralAddress, data);

        uint256 actualReferrerBalance = referralAddress.balance;
        uint256 finalProtocolFeeReceiverBalance = protocolFeeReceiver.balance;
        // check referral balance
        assertEq(actualReferrerBalance, claimFee);
        // check protocol fee receiver balance
        assertEq(
            (finalProtocolFeeReceiverBalance -
                initialProtocolFeeReceiverBalance),
            0
        );
        // Check the claims
        BoostLib.Boost memory boost = boostCore.getBoost(0);
        ERC20Incentive _incentive = ERC20Incentive(
            address(boost.incentives[0])
        );
        assertEq(_incentive.claims(), 1);
    }

```


### Mitigation


Set a maximum value for `BoostCore::referralFee` and refactor `BoostCore::createBoost` as shown below.

```diff
+ uint64 public constant MAX_REFERRER_FEE = 5000; // should be any value below 10_000
 function createBoost(bytes calldata data_)
        external
        canCreateBoost(msg.sender)
        nonReentrant
        returns (BoostLib.Boost memory)
    {
        InitPayload memory payload_ = abi.decode(data_.cdDecompress(), (InitPayload));

        // Validate the Budget
        _checkBudget(payload_.budget);

        // Initialize the Boost
        BoostLib.Boost storage boost = _boosts.push();
        boost.owner = payload_.owner;
        boost.budget = payload_.budget;
        boost.protocolFee = protocolFee + payload_.protocolFee;
        boost.referralFee = referralFee + payload_.referralFee;
+       require(boost.referralFee <= MAX_REFERRER_FEE, "referralFee is too high");
        boost.maxParticipants = payload_.maxParticipants;

        // Setup the Boost components
        boost.action = AAction(_makeTarget(type(AAction).interfaceId, payload_.action, true));
        boost.allowList = AAllowList(_makeTarget(type(AAllowList).interfaceId, payload_.allowList, true));
        boost.incentives = _makeIncentives(payload_.incentives, payload_.budget);
        boost.validator = AValidator(
            payload_.validator.instance == address(0)
                ? boost.action.supportsInterface(type(AValidator).interfaceId) ? address(boost.action) : address(0)
                : _makeTarget(type(AValidator).interfaceId, payload_.validator, true)
        );
        emit BoostCreated(
            _boosts.length - 1,
            boost.owner,
            address(boost.action),
            boost.incentives.length,
            address(boost.validator),
            address(boost.allowList),
            address(boost.budget)
        );
        return boost;
    }

```

# Issue M-2: Budget allocation will break in case of a fee on transfer ERC 20 token 

Source: https://github.com/sherlock-audit/2024-06-boost-aa-wallet-judging/issues/325 

## Found by 
0xDemon, 0xbranded, 0xbrivan, 0xsome, 4b, AresAudits, Atharv, Aycozzynfada, DenTonylifer, Galturok, IvanFitro, Japy69, KungFuPanda, KupiaSec, MSK, MSaptarshi, MrCrowNFT, ParthMandale, Pheonix, TessKimy, dimulski, ge6a, haxagon, iamnmt, ihtishamsudo, nikhilx0111, oxelmiguel, sakshamguruji, tmotfl, y4y
### Summary

[Docs ](https://audits.sherlock.xyz/contests/426?filter=questions) mention that the protocol should work with all kinds of weird tokens but a fee on transfer token won't be allocated to the budget since the allocate function in ManagedBudget.sol reverts when the balance of the asset is lesser than the amount mentioned in the payload.

### Root Cause

[`ManagedBudget.sol:71`](https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/main/boost-protocol/packages/evm/contracts/budgets/ManagedBudget.sol#L71): This check prevents the use of fee on transfer tokens since the allocated tokens actually transferred to the contract's balance will always be lesser than the payload amount owing to the fee component. 

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

The protocol will not be able to use fee on transfer tokens which they clearly want to use according to the questionnaire they answered.

### PoC

This is  a mock ERC20 fee on transfer token used for the POC
```solidity 
contract FeeOnTransferMockERC20 is ERC20("MOCK","MOCK"){
    uint FEE = 10000;
    function mint(address to, uint256 amount) public {
        _balances[to] += amount;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        require(amount > FEE);
        _balances[msg.sender] = _balances[msg.sender] - amount;
        _balances[to] = _balances[msg.sender] + amount - FEE;
        return true;
    }

    function safeTransferFrom(address from, address to, uint amount) public {
        transferFrom(from, to, amount);
    }
    function transferFrom(address from, address to, uint amount)  public override returns(bool){
        require(amount > FEE);
        _balances[from] = _balances[from] - amount;
        _balances[to] = _balances[from] + amount - FEE;
        return true;
    }

    function mintPayable(address to, uint256 amount) public payable {
        require(msg.value >= amount / 100, "MockERC20: gimme more money!");
        mint(to, amount);
    }
}
```
The test to be added to ManagedBudget.t.sol to replicate the results

```solidity
function testFeeOnTransfer() public{
        //deploy a feeon transfer mock token and mint tokens to this address
        mockFeeOnTransferERC20 = new FeeOnTransferMockERC20();
        mockFeeOnTransferERC20.mint(address(this), 100 ether);

        managedBudget = ManagedBudget(payable(LibClone.clone(address(new ManagedBudget()))));
        managedBudget.initialize(
            abi.encode(
                ManagedBudget.InitPayload({owner: address(this), authorized: new address[](0), roles: new uint256[](0)})
            )
        );
        mockFeeOnTransferERC20.approve(address(managedBudget), 100 ether);
        bytes memory data = _makeFungibleTransfer(ABudget.AssetType.ERC20, address(mockFeeOnTransferERC20), address(this), 100 ether);
        vm.expectRevert(abi.encodeWithSelector(ABudget.InvalidAllocation.selector, address(mockFeeOnTransferERC20), uint256(100 ether)));
        managedBudget.allocate(data);

    }
```
The test passes which means the `managedBudget.allocate(data)` call reverts with an `InvalidAllocation` error

### Mitigation

This one is tricky since there are 2 paths the sponsor can take:
1. Remove the support for fee on transfer tokens and mention this explicitly 
2. Keep supporting fee on transfer tokens and remove the aforementioned check. 

# Issue M-3: ERC20Incentive raffles can be gamed due to pseudorandomness 

Source: https://github.com/sherlock-audit/2024-06-boost-aa-wallet-judging/issues/356 

## Found by 
0rpse, 0x539.eth, 0xSecuri, 0xbranded, 0xbrivan, 0xloophole, 4b, Atharv, Japy69, Okazaki, Pheonix, blutorque, ctf\_sec, denzi\_, frndz0ne, ge6a, haxagon, oxelmiguel, pwning\_dev, sakshamguruji, tinnohofficial
## Summary
ERC20Incentive raffle strategy uses pseudo randomness, users can compute the outcome of raffles and frontrun the drawRaffle function call to game raffles.
## Vulnerability Detail
Users can compute the outcome of raffles due to pseudorandomness used in raffles and frontrun the transaction of the owner to win raffles depending on the outcome. Note that users are able to sit on signatures as they do not include expiration.
https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/78930f2ed6570f30e356b5529bd4bcbe5194eb8b/boost-protocol/packages/evm/contracts/incentives/ERC20Incentive.sol#L137-L146
```solidity
    function drawRaffle() external override onlyOwner {
        if (strategy != Strategy.RAFFLE) revert BoostError.Unauthorized();


        LibPRNG.PRNG memory _prng = LibPRNG.PRNG({state: block.prevrandao + block.timestamp});


        address winnerAddress = entries[_prng.next() % entries.length];


        asset.safeTransfer(winnerAddress, reward);
        emit Claimed(winnerAddress, abi.encodePacked(asset, winnerAddress, reward));
    }
```
If a user tries to take an entry in the raffle right before owner calls this function, an attacker can choose to place their entry before or after the user's to game the raffle. 

## Impact
Raffles can be gamed.

## Tool used

Manual Review

## Recommendation
Use an oracle service to provide randomness.

# Issue M-4: The incentive contracts are not compatible with rebasing/deflationary/inflationary tokens 

Source: https://github.com/sherlock-audit/2024-06-boost-aa-wallet-judging/issues/460 

## Found by 
0xNirix, 0xbranded, 0xdeadbeef, Atharv, ZanyBonzy, denzi\_, ge6a, haxagon
## Summary

The protocol wants to work with all kind of tokens including rebasing tokens. From 
[weirdERC20](https://github.com/d-xo/weird-erc20/tree/main) we can read more about Balance Modfications Outisde of Transfers (rebasing/airdrops) section which states

> Some tokens may make arbitrary balance modifications outside of transfers (e.g. Ampleforth style rebasing tokens, Compound style airdrops of governance tokens, mintable/burnable tokens).

> Some smart contract systems cache token balances (e.g. Balancer, Uniswap-V2), and arbitrary modifications to underlying balances can mean that the contract is operating with outdated information.

## Vulnerability Detail

One such example of not supporting in the code is the `ERC20Incentive::clawback()` function

```solidity
function clawback(bytes calldata data_) external override onlyOwner returns (bool) {
        ClawbackPayload memory claim_ = abi.decode(data_, (ClawbackPayload));
        (uint256 amount) = abi.decode(claim_.data, (uint256));

        if (strategy == Strategy.RAFFLE) {
            // Ensure the amount is the full reward and there are no raffle entries, then reset the limit
            if (amount != reward || claims > 0) revert BoostError.ClaimFailed(msg.sender, abi.encode(claim_));
            limit = 0;
        } else {
            // Ensure the amount is a multiple of the reward and reduce the max claims accordingly
            if (amount % reward != 0) revert BoostError.ClaimFailed(msg.sender, abi.encode(claim_));
            limit -= amount / reward;
        }
```

The variable `reward` is being used in these if conditions, reward is set during initialization of the contract. It is either set as the full amount for raffles or the amount of reward per person for pools.

Lets consider the raffle situation for this report.

In the `initialize()` function, suppose that the reward amount in the data is sent as `10e18`, this is set as reward for the raffle after confirming by checking the balance of the contract.

Now suppose after some time the balance has changed due to rebasing. The reward variable is still 10e18 but the actual balance of the contract is different.

In the `clawback()` function, the owner wants to withdraw the full amount of the raffle. If they provide the rebased balance of the contract, the function will revert due to the following if condition

```solidity
if (amount != reward || claims > 0) revert BoostError.ClaimFailed(msg.sender, abi.encode(claim_));
```

If they provide 10e18 as amount which was the original amount and the current balance of the contract is lower then the following line will cause a revert

```solidity
asset.safeTransfer(claim_.target, amount);
```

This is only one instance of an issue, these issues are present in the Incentive contracts which use ERC20s.

Similarly `ERC20Incentive::drawRaffle()` will also not work if the actual balance of the contract has changed to a lower amount.


## Impact

The balances are outdated and will cause hindrances for all parties involved. Denial of Service when the balances rebase. 

## Code Snippet

[ERC20VariableIncentive.sol](https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/main/boost-protocol/packages/evm/contracts/incentives/ERC20VariableIncentive.sol)

[ERC20Incentive.sol](https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/main/boost-protocol/packages/evm/contracts/incentives/ERC20Incentive.sol#L1-L147)

[CGDAIncentive.sol](https://github.com/sherlock-audit/2024-06-boost-aa-wallet/blob/main/boost-protocol/packages/evm/contracts/incentives/CGDAIncentive.sol)

## Tool used

Manual Review

## Recommendation

Track the balances after each transfer in/out to keep updated data in the contracts.
