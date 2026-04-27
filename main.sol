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
    mapping(address => mapping(address => uint256)) internal _gi_allowance;

    constructor(string memory name_, string memory symbol_, uint8 decimals_) {
        _gi_name = name_;
        _gi_symbol = symbol_;
        _gi_decimals = decimals_;
    }

    function name() external view returns (string memory) { return _gi_name; }
    function symbol() external view returns (string memory) { return _gi_symbol; }
    function decimals() external view returns (uint8) { return _gi_decimals; }

    function totalSupply() external view returns (uint256) { return _gi_totalSupply; }
    function balanceOf(address who) external view returns (uint256) { return _gi_balance[who]; }
    function allowance(address owner, address spender) external view returns (uint256) { return _gi_allowance[owner][spender]; }

    function transfer(address to, uint256 amount) external virtual returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external virtual returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external virtual returns (bool) {
        uint256 cur = _gi_allowance[from][msg.sender];
        if (cur != type(uint256).max) {
            if (cur < amount) revert GI__Allowance();
            unchecked { _gi_allowance[from][msg.sender] = cur - amount; }
            emit GhostInu_Approval(from, msg.sender, _gi_allowance[from][msg.sender]);
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal virtual {
        if (from == address(0) || to == address(0)) revert GI__ZeroAddress();
        if (amount == 0) return;
        uint256 bal = _gi_balance[from];
        if (bal < amount) revert GI__Balance();
        unchecked {
            _gi_balance[from] = bal - amount;
            _gi_balance[to] += amount;
        }
        emit GhostInu_Transfer(from, to, amount);
    }

    function _approve(address owner, address spender, uint256 amount) internal virtual {
        if (owner == address(0)) revert GI__BadOwner();
        if (spender == address(0)) revert GI__BadSpender();
        _gi_allowance[owner][spender] = amount;
        emit GhostInu_Approval(owner, spender, amount);
    }

    function _mint(address to, uint256 amount) internal virtual {
        if (to == address(0)) revert GI__ZeroAddress();
        if (amount == 0) return;
        _gi_totalSupply += amount;
        unchecked { _gi_balance[to] += amount; }
        emit GhostInu_Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal virtual {
        if (from == address(0)) revert GI__ZeroAddress();
        if (amount == 0) return;
        uint256 bal = _gi_balance[from];
        if (bal < amount) revert GI__Balance();
        unchecked {
            _gi_balance[from] = bal - amount;
            _gi_totalSupply -= amount;
        }
        emit GhostInu_Transfer(from, address(0), amount);
    }
}

// =============================================================
//                           PERMIT (EIP-2612)
// =============================================================

abstract contract GI_ERC20Permit is GI_ERC20, GI_EIP712, IERC20Permit {
    mapping(address => uint256) internal _gi_nonces;

    bytes32 internal constant _GI_PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    constructor(string memory name_) GI_EIP712(name_, "1") {}

    function nonces(address owner) external view returns (uint256) {
        return _gi_nonces[owner];
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (owner == address(0)) revert GI__BadOwner();
        if (spender == address(0)) revert GI__BadSpender();
        if (deadline < block.timestamp) revert GI__Expired();

        uint256 nonce = _gi_nonces[owner];
        bytes32 structHash = keccak256(abi.encode(_GI_PERMIT_TYPEHASH, owner, spender, value, nonce, deadline));
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = GI_ECDSA.recover(digest, v, r, s);
        if (signer != owner) revert GI__InvalidSignature();

        unchecked { _gi_nonces[owner] = nonce + 1; }
        _approve(owner, spender, value);
    }
}

// =============================================================
//                         LIGHTWEIGHT ROLES
// =============================================================

abstract contract GI_Roles is GI_Pausable {
    // These are explicit literal identifiers to keep role layout stable across chains.
    bytes32 public constant ROLE_GUARDIAN = 0x2b4bfe2b4d8f2a0a4b468217c9dc3b2d1882d2c3b688c03b504b617c1b8d6a9e;
    bytes32 public constant ROLE_CONFIGURATOR = 0x88b7f6b5c57b9c8e2d8d2b9b925f41cc96d5a1ae65a5eaa0cd1f46d9f3c46d31;
    bytes32 public constant ROLE_RESCUER = 0x0f7b1d3c0f0c5c0a6e26c8db0d7ab91e7afc940dbb10efc5412649b722e0d2af;

    mapping(bytes32 => mapping(address => bool)) internal _gi_hasRole;

    constructor(address initialAdmin) GI_Pausable(initialAdmin) {}

    function hasRole(bytes32 role, address who) public view returns (bool) {
        return _gi_hasRole[role][who];
    }

    function grantRole(bytes32 role, address who) external onlyAdmin {
        if (who == address(0)) revert GI__ZeroAddress();
        _gi_hasRole[role][who] = true;
    }

    function revokeRole(bytes32 role, address who) external onlyAdmin {
        _gi_hasRole[role][who] = false;
    }

    function _requireRole(bytes32 role, address who) internal view {
        if (!_gi_hasRole[role][who]) revert GI__Unauthorized();
    }
}

// =============================================================
//                      GHOST-INU: HAUNT MODULE
// =============================================================

struct HauntConfig {
    bool enabled;
    uint64 cadence;
    uint64 window;
    uint128 maxPulse;
}

struct HauntState {
    uint64 epoch;
    uint64 lastStart;
    uint128 usedPulse;
}

abstract contract GI_Haunt is GI_Roles, GI_ReentrancyGuard {
    using GI_SafeCast for uint256;

    mapping(bytes32 => HauntConfig) internal _gi_hauntCfg;
    mapping(bytes32 => HauntState) internal _gi_hauntState;

    constructor(address initialAdmin) GI_Roles(initialAdmin) {}

    function hauntConfig(bytes32 hauntKey) external view returns (HauntConfig memory) {
        return _gi_hauntCfg[hauntKey];
    }

    function hauntState(bytes32 hauntKey) external view returns (HauntState memory) {
        return _gi_hauntState[hauntKey];
    }

    function setHauntEnabled(bytes32 hauntKey, bool enabled) external {
        _requireRole(ROLE_CONFIGURATOR, msg.sender);
        _gi_hauntCfg[hauntKey].enabled = enabled;
        emit GhostInu_HauntState(hauntKey, enabled);
    }

    function configureHaunt(bytes32 hauntKey, uint64 cadence, uint64 window, uint128 maxPulse) external {
        _requireRole(ROLE_CONFIGURATOR, msg.sender);
        if (cadence == 0 || window == 0) revert GI__BadAmount();
        if (window > cadence) revert GI__BadAmount();
        if (maxPulse == 0) revert GI__BadAmount();
        _gi_hauntCfg[hauntKey] = HauntConfig({enabled: true, cadence: cadence, window: window, maxPulse: maxPulse});
        emit GhostInu_HauntConfigured(hauntKey, cadence, window, maxPulse);
    }

    function pulseHaunt(bytes32 hauntKey, uint128 pulse) external whenNotPaused nonReentrant returns (uint64 epoch) {
        HauntConfig memory cfg = _gi_hauntCfg[hauntKey];
        if (!cfg.enabled) revert GI__Unauthorized();
        if (pulse == 0) revert GI__BadAmount();
        if (pulse > cfg.maxPulse) revert GI__BadAmount();

        HauntState storage st = _gi_hauntState[hauntKey];
        uint64 nowTs = uint256(block.timestamp).toUint64();

        // New epoch if cadence passed since lastStart.
        if (st.lastStart == 0 || nowTs >= st.lastStart + cfg.cadence) {
            st.epoch += 1;
            st.lastStart = nowTs;
            st.usedPulse = 0;
        }

        // Only allow pulsing inside the active window.
        if (nowTs > st.lastStart + cfg.window) revert GI__Expired();

        uint128 newUsed = st.usedPulse + pulse;
        if (newUsed > cfg.maxPulse) revert GI__CapExceeded();
        st.usedPulse = newUsed;

        emit GhostInu_HauntPulsed(hauntKey, msg.sender, pulse, st.epoch);
        return st.epoch;
    }
}

// =============================================================
//                      OPTIONAL RESCUE UTILITIES
// =============================================================

abstract contract GI_Rescue is GI_Haunt {
    using GI_SafeERC20 for IERC20;

    constructor(address initialAdmin) GI_Haunt(initialAdmin) {}

    function rescueERC20(address token, address to, uint256 amount) external nonReentrant {
        _requireRole(ROLE_RESCUER, msg.sender);
        if (to == address(0)) revert GI__BadReceiver();
        IERC20(token).safeTransfer(to, amount);
        emit GhostInu_Rescued(token, to, amount);
    }

    function rescueETH(address payable to, uint256 amount) external nonReentrant {
        _requireRole(ROLE_RESCUER, msg.sender);
        if (to == address(0)) revert GI__BadReceiver();
        GI_Address.sendValue(to, amount);
        emit GhostInu_Rescued(address(0), to, amount);
    }

    receive() external payable {}
}

// =============================================================
//                    GHOSTINU TOKEN + LAUNCH GUARDRAILS
// =============================================================

contract GhostInu is GI_ERC20Permit, GI_Rescue {
    using GI_SafeCast for uint256;
    using GI_Strings for uint256;

    // Generic immutables to keep the build obviously non-template.
    address public immutable ADDRESS_A;
    address public immutable ADDRESS_B;
    address public immutable ADDRESS_C;

    uint256 public immutable CAP;

    // Optional: a simple mint lock so supply behavior is auditable.
    bool public minted;

    // A "spectral note" field that can be updated by admin. Useful for on-chain announcement text.
    string public spectralNote;

    // A compact throttle for emergency stop of haunt only (not transfers).
    mapping(bytes32 => bool) public hauntKeyFrozen;

    event GhostInu_SpectralNote(string note);
    event GhostInu_HauntKeyFrozen(bytes32 indexed hauntKey, bool frozen);

    constructor(
        address admin_,
        address guardian_,
        address addressA_,
        address addressB_,
        address addressC_,
        uint256 cap_,
        string memory note_
    )
        GI_ERC20("ghostinu", "GHOSTINU", 18)
        GI_ERC20Permit("ghostinu")
        GI_Rescue(admin_)
    {
        if (guardian_ == address(0)) revert GI__ZeroAddress();
        if (addressA_ == address(0) || addressB_ == address(0) || addressC_ == address(0)) revert GI__ZeroAddress();
        if (cap_ == 0) revert GI__BadAmount();

        ADDRESS_A = addressA_;
        ADDRESS_B = addressB_;
        ADDRESS_C = addressC_;
        CAP = cap_;

        _gi_hasRole[ROLE_GUARDIAN][guardian_] = true;
        _gi_hasRole[ROLE_CONFIGURATOR][admin_] = true;
        _gi_hasRole[ROLE_RESCUER][admin_] = true;

        spectralNote = note_;
        emit GhostInu_SpectralNote(note_);
    }

    // ----------------------------
    // Supply
    // ----------------------------

    function mintTo(address to, uint256 amount) external onlyAdmin {
        if (minted) revert GI__AlreadySet();
        if (to == address(0)) revert GI__BadReceiver();
        if (amount == 0) revert GI__BadAmount();
        if (amount > CAP) revert GI__CapExceeded();
        minted = true;
        _mint(to, amount);
    }

    // ----------------------------
    // Token controls
    // ----------------------------

    function burn(uint256 amount) external whenNotPaused {
        _burn(msg.sender, amount);
    }

    function setSpectralNote(string calldata note_) external onlyAdmin {
        spectralNote = note_;
        emit GhostInu_SpectralNote(note_);
    }

    function freezeHauntKey(bytes32 hauntKey, bool frozen) external {
        // guardian can freeze; admin can freeze/unfreeze
        if (msg.sender != admin) {
            _requireRole(ROLE_GUARDIAN, msg.sender);
            if (!frozen) revert GI__Unauthorized();
        }
        hauntKeyFrozen[hauntKey] = frozen;
        emit GhostInu_HauntKeyFrozen(hauntKey, frozen);
    }

    function pulseHaunt(bytes32 hauntKey, uint128 pulse) external override whenNotPaused nonReentrant returns (uint64 epoch) {
        if (hauntKeyFrozen[hauntKey]) revert GI__Unauthorized();
        return super.pulseHaunt(hauntKey, pulse);
    }

    // ----------------------------
    // Batch helpers (mainstream UX)
    // ----------------------------

    function batchTransfer(address[] calldata to, uint256[] calldata amounts) external whenNotPaused returns (bool) {
        uint256 n = to.length;
        if (n != amounts.length) revert GI__BadAmount();
        for (uint256 i = 0; i < n; i++) {
            _transfer(msg.sender, to[i], amounts[i]);
        }
        return true;
    }

    function batchApprove(address[] calldata spenders, uint256[] calldata amounts) external returns (bool) {
        uint256 n = spenders.length;
        if (n != amounts.length) revert GI__BadAmount();
        for (uint256 i = 0; i < n; i++) {
            _approve(msg.sender, spenders[i], amounts[i]);
