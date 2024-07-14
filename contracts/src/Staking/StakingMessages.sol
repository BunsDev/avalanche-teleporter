// (c) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.18;

library StakingMessages {
    // Subnets send a RegisterSubnetValidator message to the P-Chain to register a validator.
    uint32 internal constant REGISTER_SUBNET_VALIDATOR_TYPE_ID = 1;
    // The P-Chain sends a SubnetValidatorRegistered message to the subnet to confirm the validator has been registered.
    uint32 internal constant SUBNET_VALIDATOR_REGISTERED_TYPE_ID = 2;
    // Subnets can send a SetSubnetValidatorWeight message to the P-Chain to update a validator's weight.
    uint32 internal constant SET_SUBNET_VALIDATOR_WEIGHT_TYPE_ID = 3;
    // The P-Chain sends a SubnetValidatorWeightSet message to the subnet to confirm the validator's weight has been updated.
    uint32 internal constant SUBNET_VALIDATOR_WEIGHT_SET_TYPE_ID = 4;
    // The P-Chain sends a ValidationPeriodInvalidated message to the Subnet to confirm that the validation period has
    // is not active and will never be active. This can either be due to the validation period ending, or it never
    // being successfully registered prior to its registry expiry.
    uint32 internal constant VALIDATION_PERIOD_INVALIDATED_TYPE_ID = 5;

    // The information that uniquely identifies a subnet validation period.
    // The SHA-256 hash of the concatenation of these field is the validationID.
    struct ValidationInfo {
        bytes32 subnetID;
        bytes32 nodeID;
        uint64 weight;
        uint64 registrationExpiry;
        bytes signature;
    }

    function packRegisterSubnetValidatorMessage(ValidationInfo memory valiationInfo)
        internal
        pure
        returns (bytes32, bytes memory)
    {
        (bytes32 validationID, bytes memory serializedValidationInfo) =
            serializeValidationInfo(valiationInfo);

        bytes memory res = new bytes(148);
        // Pack the message type
        for (uint256 i; i < 4; ++i) {
            res[i] = bytes1(uint8(REGISTER_SUBNET_VALIDATOR_TYPE_ID >> (8 * (3 - i))));
        }
        // Pack the validation info
        for (uint256 i; i < 144; ++i) {
            res[i + 4] = serializedValidationInfo[i];
        }

        return (validationID, res);
    }

    function unpackSubnetValidatorRegisteredMessage(bytes memory input)
        internal
        pure
        returns (bytes32, ValidationInfo memory)
    {
        return unpackValidationMessage(SUBNET_VALIDATOR_REGISTERED_TYPE_ID, input);
    }

    function unpackValidationPeriodInvalidatedMessage(bytes memory input)
        internal
        pure
        returns (bytes32, ValidationInfo memory)
    {
        return unpackValidationMessage(VALIDATION_PERIOD_INVALIDATED_TYPE_ID, input);
    }

    function unpackValidationMessage(
        uint32 expectedMessageType,
        bytes memory input
    ) internal pure returns (bytes32, ValidationInfo memory) {
        require(input.length == 148, "StakingMessages: Invalid message length");
        // Unpack the message type.
        uint32 messageType;
        for (uint256 i; i < 4; ++i) {
            messageType |= uint32(uint8(input[i])) << uint32((8 * (3 - i)));
        }
        require(messageType == expectedMessageType, "StakingMessages: Invalid message type");

        bytes memory serializedValidationInfo = new bytes(144);
        // Unpack the validation info
        for (uint256 i; i < 144; ++i) {
            serializedValidationInfo[i] = input[i + 4];
        }
        return deserializeValidationInfo(serializedValidationInfo);
    }

    function serializeValidationInfo(ValidationInfo memory validationInfo)
        internal
        pure
        returns (bytes32, bytes memory)
    {
        require(validationInfo.signature.length == 64, "StakingMessages: Invalid signature length");
        bytes memory res = new bytes(144);
        // Pack the subnetID
        for (uint256 i; i < 32; ++i) {
            res[i] = validationInfo.subnetID[i];
        }
        // Pack the nodeID
        for (uint256 i; i < 32; ++i) {
            res[i + 32] = validationInfo.nodeID[i];
        }
        // Pack the weight
        for (uint256 i; i < 8; ++i) {
            res[i + 64] = bytes1(uint8(validationInfo.weight >> uint8((8 * (7 - i)))));
        }
        // Pack the registration expiry
        for (uint256 i; i < 8; ++i) {
            res[i + 72] = bytes1(uint8(validationInfo.registrationExpiry >> uint64((8 * (7 - i)))));
        }
        // Pack the signature
        for (uint256 i; i < 64; ++i) {
            res[i + 80] = validationInfo.signature[i];
        }
        return (sha256(res), res);
    }

    function deserializeValidationInfo(bytes memory input)
        internal
        pure
        returns (bytes32, ValidationInfo memory)
    {
        require(input.length == 144, "StakingMessages: Invalid message length");
        bytes32 validationID = sha256(input);
        ValidationInfo memory validationInfo;
        // Unpack the subnetID
        uint256 subnetIDValue;
        for (uint256 i; i < 32; ++i) {
            subnetIDValue = (subnetIDValue << 8) | uint256(uint8(input[i]));
        }
        validationInfo.subnetID = bytes32(subnetIDValue);
        // Unpack the nodeID
        uint256 nodeIDValue;
        for (uint256 i; i < 32; ++i) {
            nodeIDValue = (nodeIDValue << 8) | uint256(uint8(input[i + 32]));
        }
        validationInfo.nodeID = bytes32(nodeIDValue);
        // Unpack the weight
        for (uint256 i; i < 8; ++i) {
            validationInfo.weight |= uint64(uint8(input[i + 64])) << uint64((8 * (7 - i)));
        }
        // Unpack the registration expiry
        for (uint256 i; i < 8; ++i) {
            validationInfo.registrationExpiry |=
                uint64(uint8(input[i + 72])) << uint64((8 * (7 - i)));
        }
        // Unpack the signature
        for (uint256 i; i < 64; ++i) {
            validationInfo.signature[i] = input[i + 80];
        }
        return (validationID, validationInfo);
    }
}
