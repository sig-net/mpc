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
    uint256 private constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function ecMul(uint256 _k, uint256 _x, uint256 _y) internal pure returns (uint256, uint256) {
        return EllipticCurve.ecMul(_k, _x, _y, A, P);
    }

    function ecAdd(uint256 _x1, uint256 _y1, uint256 _x2, uint256 _y2) internal pure returns (uint256, uint256) {
        return EllipticCurve.ecAdd(_x1, _y1, _x2, _y2, A, P);
    }

    /// @dev recovers signer public key point value.
    /// @param digest hashed message
    /// @param v recovery
    /// @param r first 32 bytes of signature
    /// @param v last 32 bytes of signature
    /// @return (x, y) EC point
    function recover(
        uint256 digest,
        uint8 v,
        uint256 r,
        uint256 s
    ) internal pure returns (uint256, uint256) {
        uint256 x = addmod(r, P * (v >> 1), P);
        if (x > P || s > N || r > N || s == 0 || r == 0 || v > 1) {
            return (0, 0);
        }
        uint256 rInv = EllipticCurve.invMod(r, N);

        uint256 y2 = addmod(mulmod(x, mulmod(x, x, P), P), addmod(mulmod(x, A, P), B, P), P);
        y2 = EllipticCurve.expMod(y2, (P + 1) / 4, P);
        uint256 y = ((y2 + v + 2) & 1 == 0) ? y2 : P - y2;

        (uint256 qx, uint256 qy, uint256 qz) = EllipticCurve.jacMul(mulmod(rInv, N - digest, N), GX, GY, 1, A, P);
        (uint256 qx2, uint256 qy2, uint256 qz2) = EllipticCurve.jacMul(mulmod(rInv, s, N), x, y, 1, A, P);
        (uint256 qx3, uint256 qy3) = EllipticCurve.ecAdd(qx, qy, qz, qx2, qy2, qz2);

        return (qx3, qy3);
    }
}
