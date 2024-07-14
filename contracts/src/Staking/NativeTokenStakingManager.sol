// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.18;

import {INativeTokenStakingManager} from "./interfaces/INativeTokenStakingManager.sol";
import {
    WarpMessage,
    IWarpMessenger
} from "@avalabs/subnet-evm-contracts@1.2.0/contracts/interfaces/IWarpMessenger.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts@4.8.1/security/ReentrancyGuard.sol";
import {StakingMessages} from "./StakingMessages.sol";
import {IRewardCalculator} from "./interfaces/IRewardCalculator.sol";

contract NativeTokenStakingManager is ReentrancyGuard, INativeTokenStakingManager {
    enum ValidatorStatus {
        PendingAdded,
        Active,
        PendingRemoved,
        Completed
    }

    struct Validator {
        ValidatorStatus status;
        bytes32 nodeID;
        uint64 weight;
        uint64 startedAt;
        uint64 endedAt;
        address owner;
        bool rewarded;
    }

    struct ValidatorChrunPeriod {
        uint256 startedAt;
        uint64 initialStake;
        uint64 churnAmount;
    }

    // solhint-disable private-vars-leading-underscore
    /// @custom:storage-location erc7201:avalanche-icm.storage.NativeTokenStakingManager
    struct NativeTokenStakingManagerStorage {
        IWarpMessenger _warpMessenger;
        bytes32 _subnetID;
        uint256 _minimumStakeAmount;
        uint256 _maximumStakeAmount;
        IRewardCalculator _rewardCalculator;
        uint8 _maximumHourlyChurn;
        uint64 _remainingInitialStake;
        ValidatorChrunPeriod _churnTracker;
        // Maps the validationID to the registration message such that the message can be re-sent if needed.
        mapping(bytes32 => bytes) _pendingRegisterValidationMessages;
        // Maps the validationID to the validator information.
        mapping(bytes32 => Validator) _validationPeriods;
        // Maps the nodeID to the validationID for active validation periods.
        mapping(bytes32 => bytes32) _activeValidators;
    }

    // solhint-enable private-vars-leading-underscore
    // keccak256(abi.encode(uint256(keccak256("avalanche-icm.storage.NativeTokenStakingManager")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant _NATIVE_TOKEN_STAKING_MANAGER_STORAGE_LOCATION =
        0x8568826440873e37a96cb0aab773b28d8154d963d2f0e41bd9b5c15f63625f91;

    // solhint-disable ordering
    function _getTokenHomeStorage()
        private
        pure
        returns (NativeTokenStakingManagerStorage storage $)
    {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := _NATIVE_TOKEN_STAKING_MANAGER_STORAGE_LOCATION
        }
    }

    struct InitialStakerInfo {
        StakingMessages.ValidationInfo validationInfo;
        address owner;
    }

    function initialize(
        bytes32 subnetID,
        uint256 minimumStakeAmount,
        uint256 maximumStakeAmount,
        uint8 maximumHourlyChurn,
        InitialStakerInfo[] memory initialStakers,
        IRewardCalculator rewardCalculator
    ) public {
        NativeTokenStakingManagerStorage storage $ = _getTokenHomeStorage();
        $._warpMessenger = IWarpMessenger(0x0200000000000000000000000000000000000005);
        $._subnetID = subnetID;
        $._minimumStakeAmount = minimumStakeAmount;
        $._maximumStakeAmount = maximumStakeAmount;
        $._maximumHourlyChurn = maximumHourlyChurn;
        // Add each of the initial stakers as validators
        uint64 initialStake;
        for (uint256 i; i < initialStakers.length; ++i) {
            (bytes32 validationID,) =
                StakingMessages.serializeValidationInfo(initialStakers[i].validationInfo);
            $._validationPeriods[validationID] = Validator({
                status: ValidatorStatus.Active,
                nodeID: initialStakers[i].validationInfo.nodeID,
                weight: initialStakers[i].validationInfo.weight,
                startedAt: uint64(block.timestamp),
                endedAt: 0,
                owner: initialStakers[i].owner,
                rewarded: false
            });
            initialStake += initialStakers[i].validationInfo.weight;
        }
        $._remainingInitialStake = initialStake;
        $._rewardCalculator = rewardCalculator;
    }

    /**
     * @notice Modifier to ensure that the initial stake has been provided.
     */
    modifier onlyWhenInitialStakeProvided() {
        NativeTokenStakingManagerStorage storage $ = _getTokenHomeStorage();
        require(
            $._remainingInitialStake > 0, "NativeTokenStakingManager: Initial stake not provided"
        );
        _;
    }

    /**
     * @notice Called to provide initial stake amount for original validators added prior to the contract's initialization.
     */
    function provideInitialStake() external payable {
        NativeTokenStakingManagerStorage storage $ = _getTokenHomeStorage();
        uint64 remainingInitialStake = $._remainingInitialStake;
        require(
            msg.value <= remainingInitialStake,
            "NativeTokenStakingManager: Provided stake exceeds remaining initial stake"
        );
        $._remainingInitialStake = remainingInitialStake - uint64(msg.value);
    }

    /**
     * @notice Begins the validator registration process. Locks the provided native asset in the contract as the stake.
     * @param nodeID The node ID of the validator being registered.
     * @param registrationExpiry The time at which the reigistration is no longer valid on the P-Chain.
     * @param signature The raw bytes of the Ed25519 signature over the concatenated bytes of
     * [subnetID]+[nodeID]+[blsPublicKey]+[weight]+[balance]+[expiry]. This signature must correspond to the Ed25519
     * public key that is used for the nodeID. This approach prevents NodeIDs from being unwillingly added to Subnets.
     * balance is the minimum initial $nAVAX balance that must be attached to the validator serialized as a uint64.
     * The signature field will be validated by the P-Chain. Implementations may choose to validate that the signature
     * field is well-formed but it is not required.
     */
    function initializeValidatorRegistration(
        bytes32 nodeID,
        uint64 registrationExpiry,
        bytes memory signature
    ) external payable onlyWhenInitialStakeProvided returns (bytes32) {
        NativeTokenStakingManagerStorage storage $ = _getTokenHomeStorage();

        // Ensure the registration expiry is in a valid range.
        require(
            registrationExpiry > block.timestamp && block.timestamp + 2 days > registrationExpiry,
            "NativeTokenStakingManager: Invalid registration expiry"
        );

        // Ensure the stake churn doesn't exceed the maximum churn rate.
        uint64 weight = valueToWeight(msg.value);
        _checkAndUpdateChurnTracker(weight);

        // Ensure the weight is within the valid range.
        require(
            weight >= $._minimumStakeAmount && weight <= $._maximumStakeAmount,
            "NativeTokenStakingManager: Invalid stake amount"
        );

        // Ensure the nodeID is not the zero address, and is not already an active validator.
        require(nodeID != bytes32(0), "NativeTokenStakingManager: Invalid node ID");
        require(
            $._activeValidators[nodeID] == bytes32(0),
            "NativeTokenStakingManager: Node ID already active"
        );

        // Ensure the signature is the proper length. The EVM does not provide an Ed25519 precompile to
        // validate the signature, but the P-Chain will validate the signature. If the signature is invalid,
        // the P-Chain will reject the registration, and the stake can be returned to the staker after the registration
        // expiry has passed.
        require(signature.length == 64, "NativeTokenStakingManager: Invalid signature length");

        StakingMessages.ValidationInfo memory validationInfo = StakingMessages.ValidationInfo({
            subnetID: $._subnetID,
            nodeID: nodeID,
            weight: weight,
            registrationExpiry: registrationExpiry,
            signature: signature
        });
        (bytes32 validationID, bytes memory registerSubnetValidatorMessage) =
            StakingMessages.packRegisterSubnetValidatorMessage(validationInfo);
        $._pendingRegisterValidationMessages[validationID] = registerSubnetValidatorMessage;

        // Submit the message to the Warp precompile.
        bytes32 messageID = $._warpMessenger.sendWarpMessage(registerSubnetValidatorMessage);

        Validator memory pendingValidation = Validator({
            status: ValidatorStatus.PendingAdded,
            nodeID: nodeID,
            weight: weight,
            startedAt: uint64(block.timestamp),
            endedAt: 0,
            owner: msg.sender,
            rewarded: false
        });
        $._validationPeriods[validationID] = pendingValidation;
        emit ValidationPeriodCreated(validationID, nodeID, messageID, weight, registrationExpiry);

        return validationID;
    }

    /**
     * @notice Completes the validator registration process by returning an acknowledgement of the registration of a
     * validationID from the P-Chain.
     * @param messageIndex The index of the Warp message to be received providing the acknowledgement.
     */
    function completeValidatorRegistration(uint32 messageIndex) external {}

    /**
     * @notice Begins the process of ending an active validation period. The validation period must have been previously
     * started by a successful call to {completeValidatorRegistration} with the given validationID.
     * Any rewards for this validation period will stop accruing when this function is called.
     * @param validationID The ID of the validation being ended.
     */
    function initializeEndValidation(bytes32 validationID) external {}

    /**
     * @notice Completes the process of ending a validation period by receiving an acknowledgement from the P-Chain
     * that the validation ID is not active and will never be active in the future. Returns the the stake associated
     * with the validation. Note that this function can be used for successful validation periods that have been explicitly
     * ended by calling {initializeEndValidation} or for validation periods that never began on the P-Chain due to the
     * {registrationExpiry} being reached.
     */
    function completeEndValidation(uint32 messageIndex) external {}

    /**
     * @notice Helper function to check if the stake amount to be added or removed would exceed the maximum stake churn
     * rate for the past hour. If the churn rate is exceeded, the function will revert. If the churn rate is not exceeded,
     * the function will update the churn tracker with the new amount.
     */
    function _checkAndUpdateChurnTracker(uint64 amount) private {
        NativeTokenStakingManagerStorage storage $ = _getTokenHomeStorage();
        ValidatorChrunPeriod storage churnTracker = $._churnTracker;
        uint256 currentTime = block.timestamp;
        if (currentTime - churnTracker.startedAt >= 1 hours) {
            churnTracker.churnAmount = amount;
            churnTracker.startedAt = currentTime;
        } else {
            churnTracker.churnAmount += amount;
        }

        uint8 churnPercentage = uint8((churnTracker.churnAmount * 100) / churnTracker.initialStake);
        require(
            churnPercentage <= $._maximumHourlyChurn,
            "NativeTokenStakingManager: Maximum hourly churn rate exceeded"
        );
        $._churnTracker = churnTracker;
    }

    function valueToWeight(uint256 value) public pure returns (uint64) {
        return uint64(value / 1e12);
    }

    function weightToValue(uint64 weight) public pure returns (uint256) {
        return uint256(weight) * 1e12;
    }
}
