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

library GI_SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        (bool ok, bytes memory ret) = address(token).call(data);
        if (!ok) revert GI__BadCall();
        if (ret.length > 0) {
            if (!abi.decode(ret, (bool))) revert GI__BadCall();
        }
    }
}

// =============================================================
//                      REENTRANCY GUARD
// =============================================================

abstract contract GI_ReentrancyGuard {
    uint256 private constant _GI_NOT_ENTERED = 1;
    uint256 private constant _GI_ENTERED = 2;
    uint256 private _gi_status = _GI_NOT_ENTERED;

    modifier nonReentrant() {
        if (_gi_status == _GI_ENTERED) revert GI__Reentered();
        _gi_status = _GI_ENTERED;
        _;
        _gi_status = _GI_NOT_ENTERED;
    }
}

// =============================================================
//                     TWO-STEP ADMIN CONTROL
// =============================================================

abstract contract GI_Admin2Step {
    address public admin;
    address public pendingAdmin;

    modifier onlyAdmin() {
        if (msg.sender != admin) revert GI__Unauthorized();
        _;
    }

    constructor(address initialAdmin) {
        if (initialAdmin == address(0)) revert GI__ZeroAddress();
        admin = initialAdmin;
    }

    function proposeAdmin(address next) external onlyAdmin {
        if (next == address(0)) revert GI__ZeroAddress();
        pendingAdmin = next;
        emit GhostInu_AdminProposed(admin, next);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert GI__NotPending();
        address prev = admin;
        admin = pendingAdmin;
        pendingAdmin = address(0);
        emit GhostInu_AdminAccepted(prev, admin);
    }
}

// =============================================================
//                            PAUSABLE
// =============================================================

abstract contract GI_Pausable is GI_Admin2Step {
    bool public paused;

    modifier whenNotPaused() {
        if (paused) revert GI__Paused();
        _;
    }

    constructor(address initialAdmin) GI_Admin2Step(initialAdmin) {}

    function pause() external onlyAdmin {
        if (paused) revert GI__AlreadySet();
        paused = true;
        emit GhostInu_Paused(msg.sender);
    }

    function unpause() external onlyAdmin {
        if (!paused) revert GI__AlreadySet();
        paused = false;
        emit GhostInu_Unpaused(msg.sender);
    }
}

// =============================================================
//                          EIP-712 BASE
// =============================================================

abstract contract GI_EIP712 {
    bytes32 private immutable _gi_cachedDomainSeparator;
    uint256 private immutable _gi_cachedChainId;
    address private immutable _gi_cachedThis;

    bytes32 private immutable _gi_nameHash;
    bytes32 private immutable _gi_versionHash;

    bytes32 private constant _GI_EIP712_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    constructor(string memory name_, string memory version_) {
        _gi_nameHash = keccak256(bytes(name_));
        _gi_versionHash = keccak256(bytes(version_));
        _gi_cachedChainId = block.chainid;
        _gi_cachedThis = address(this);
        _gi_cachedDomainSeparator = _buildDomainSeparator();
        emit GhostInu_EIP712Domain(_gi_cachedDomainSeparator);
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        if (address(this) == _gi_cachedThis && block.chainid == _gi_cachedChainId) {
            return _gi_cachedDomainSeparator;
        }
        return _buildDomainSeparator();
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                _GI_EIP712_TYPEHASH,
                _gi_nameHash,
                _gi_versionHash,
                block.chainid,
                address(this)
            )
        );
    }

    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash));
    }
}

// =============================================================
//                           ERC20 CORE
// =============================================================

abstract contract GI_ERC20 is IERC20, IERC20Metadata {
    string private _gi_name;
    string private _gi_symbol;
    uint8 private immutable _gi_decimals;

    uint256 internal _gi_totalSupply;
    mapping(address => uint256) internal _gi_balance;
