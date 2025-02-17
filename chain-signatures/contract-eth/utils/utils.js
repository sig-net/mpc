const { ethers } = require("ethers");

/**
 * Generates a request ID by encoding the provided parameters and hashing them using keccak256.
 *
 * @param {string} addr - The Ethereum address.
 * @param {string | Uint8Array} payload - The payload data (either a string or bytes).
 * @param {string} path - The path identifier.
 * @param {number} - The key version.
 * @param {number} - The blockchain ID.
 * @param {string} - The algorithm identifier.
 * @param {string} - The destination identifier.
 * @param {string} - Additional parameters.
 * @returns {string} The computed request ID (Keccak256 hash).
 */
function generateRequestId(addr, payload, path, keyVersion, chainId, algo, dest, params) {
    const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
        ["address", "bytes", "string", "uint32", "uint256", "string", "string", "string"],
        [addr, payload, path, keyVersion, chainId, algo, dest, params]
    );
    return ethers.keccak256(encoded);
}

module.exports = { generateRequestId };