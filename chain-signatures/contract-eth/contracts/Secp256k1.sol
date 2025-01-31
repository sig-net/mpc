// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./EllipticCurve.sol";

/**
 ** @title Secp256k1 Elliptic Curve
 ** @notice Example of particularization of Elliptic Curve for secp256k1 curve
 ** @author Witnet Foundation
 */
library Secp256k1 {
    uint256 public constant GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant A = 0;
    uint256 public constant B = 7;
    uint256 public constant P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function ecMul(uint256 _k, uint256 _x, uint256 _y) internal pure returns (uint256, uint256) {
        return EllipticCurve.ecMul(_k, _x, _y, A, P);
    }

    function ecAdd(uint256 _x1, uint256 _y1, uint256 _x2, uint256 _y2) internal pure returns (uint256, uint256) {
        return EllipticCurve.ecAdd(_x1, _y1, _x2, _y2, A, P);
    }

    function ecSub(uint256 _x1, uint256 _y1, uint256 _x2, uint256 _y2) internal pure returns (uint256, uint256) {
        return EllipticCurve.ecSub(_x1, _y1, _x2, _y2, A, P);
    }
}
