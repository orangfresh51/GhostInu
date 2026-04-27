// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
    Night-static whisper, hinge-click, glass-calm.

    GhostInu is an ERC20 with EIP-2612 permit, role-gated controls, and an optional
    on-chain "haunt" module that can be toggled by governance for community events.

    Design goals:
    - Mainnet safety: clear roles, 2-step admin handover, pausability, no hidden fees.
    - Predictable supply: fixed cap minted once at deployment.
    - Strong signature hygiene: EIP-712 + nonces, compact errors.
*/

// =============================================================
//                           ERRORS
// =============================================================

error GI__ZeroAddress();
error GI__Unauthorized();
error GI__Paused();
error GI__BadAmount();
error GI__BadNonce();
error GI__Expired();
error GI__InvalidSignature();
error GI__Allowance();
error GI__Balance();
error GI__CapExceeded();
error GI__AlreadySet();
error GI__NotPending();
error GI__Reentered();
error GI__BadReceiver();
error GI__BadSpender();
error GI__BadOwner();
error GI__BadDeadline();
error GI__BadCall();

// =============================================================
//                           EVENTS
// =============================================================

event GhostInu_Transfer(address indexed from, address indexed to, uint256 amount);
event GhostInu_Approval(address indexed owner, address indexed spender, uint256 amount);
event GhostInu_Paused(address indexed by);
event GhostInu_Unpaused(address indexed by);
event GhostInu_AdminProposed(address indexed currentAdmin, address indexed pendingAdmin);
event GhostInu_AdminAccepted(address indexed previousAdmin, address indexed newAdmin);
event GhostInu_GuardianSet(address indexed previousGuardian, address indexed newGuardian);
event GhostInu_HauntConfigured(bytes32 indexed hauntKey, uint64 cadence, uint64 window, uint128 maxPulse);
event GhostInu_HauntPulsed(bytes32 indexed hauntKey, address indexed by, uint128 pulse, uint64 epoch);
event GhostInu_HauntState(bytes32 indexed hauntKey, bool enabled);
event GhostInu_Rescued(address indexed token, address indexed to, uint256 amount);
event GhostInu_EIP712Domain(bytes32 indexed domainSeparator);

// =============================================================
//                        INTERFACES
// =============================================================

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC20Metadata is IERC20 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
}

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
    function nonces(address owner) external view returns (uint256);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

// =============================================================
//                         LIBRARIES
// =============================================================

library GI_Strings {
    function toString(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 j = v;
        uint256 len;
        while (j != 0) {
            unchecked { len++; j /= 10; }
        }
        bytes memory out = new bytes(len);
        uint256 k = len;
        while (v != 0) {
            unchecked {
                k--;
                out[k] = bytes1(uint8(48 + (v % 10)));
                v /= 10;
            }
        }
        return string(out);
    }
}

library GI_Math {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }
}

library GI_SafeCast {
    function toUint128(uint256 v) internal pure returns (uint128) {
        if (v > type(uint128).max) revert GI__BadAmount();
        return uint128(v);
    }

    function toUint64(uint256 v) internal pure returns (uint64) {
        if (v > type(uint64).max) revert GI__BadAmount();
        return uint64(v);
    }
}

library GI_Address {
    function isContract(address a) internal view returns (bool) {
        return a.code.length != 0;
    }

    function sendValue(address payable to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert GI__BadCall();
    }
}

library GI_ECDSA {
    function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert GI__InvalidSignature();
        return signer;
    }
}
