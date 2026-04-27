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
