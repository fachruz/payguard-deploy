// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal ERC-20 interface — all PayGuard needs from the payment token.
/// @dev Declared locally so the project has zero external dependencies.
///      The vault is decimals-agnostic: every amount is in the token's own
///      smallest unit (for Aevum's tUSD8 that is 6 decimals).
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title PayGuardVault — a session-key payment vault for AI agents
/// @notice The owner deposits an ERC-20 (on Aevum: tUSD8) and grants an agent
///         a scoped "session key": the agent may pay only allowlisted
///         recipients, only up to a per-transaction cap, only up to a total
///         session budget, and only until the session expires. Payments above
///         an approval threshold wait in a queue for the owner's explicit
///         approve/reject. The owner can revoke a session instantly. Every
///         action emits an event, forming a public on-chain audit trail.
///
///         The session key is just the agent's own EOA calling `pay` — it is
///         NOT the owner's key and can never move funds outside the rules
///         above. Least privilege is enforced by the contract, not by trust.
contract PayGuardVault {
    // ------------------------------------------------------------------
    // Types
    // ------------------------------------------------------------------

    struct Session {
        address agent; // the session key holder (an EOA separate from the owner)
        uint256 perTxCap; // hard ceiling for a single payment
        uint256 approvalThreshold; // above this (and <= cap) a payment queues for owner approval
        uint256 sessionBudget; // hard ceiling for total executed spend in this session
        uint256 spent; // total executed so far (queued payments do not count until approved)
        uint256 expiry; // unix timestamp; the session is dead at and after this time
        bool revoked; // owner killed the session instantly
        bool exists;
    }

    enum PaymentStatus {
        Pending, // queued, waiting for the owner
        Executed, // tokens moved to the recipient
        Rejected // owner refused; funds never left the vault
    }

    struct Payment {
        uint256 sessionId;
        address to;
        uint256 amount;
        PaymentStatus status;
    }

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    IERC20 public immutable token;
    address public immutable owner;

    uint256 public sessionCount;
    uint256 public paymentCount;

    mapping(uint256 => Session) private _sessions;
    mapping(uint256 => Payment) private _payments;
    /// @dev sessionId => recipient => allowed
    mapping(uint256 => mapping(address => bool)) private _allowlist;

    // ------------------------------------------------------------------
    // Audit trail (events)
    // ------------------------------------------------------------------

    event Deposited(address indexed owner, uint256 amount);
    event Withdrawn(address indexed owner, uint256 amount);
    event SessionCreated(
        uint256 indexed sessionId,
        address indexed agent,
        uint256 perTxCap,
        uint256 approvalThreshold,
        uint256 sessionBudget,
        uint256 expiry
    );
    event PaymentQueued(uint256 indexed paymentId, uint256 indexed sessionId, address indexed to, uint256 amount);
    event PaymentExecuted(uint256 indexed paymentId, uint256 indexed sessionId, address indexed to, uint256 amount);
    event PaymentApproved(uint256 indexed paymentId, uint256 indexed sessionId);
    event PaymentRejected(uint256 indexed paymentId, uint256 indexed sessionId);
    event SessionRevoked(uint256 indexed sessionId, address indexed agent);

    // ------------------------------------------------------------------
    // Construction & modifiers
    // ------------------------------------------------------------------

    constructor(address tokenAddress) {
        require(tokenAddress != address(0), "PayGuard: token address is zero");
        token = IERC20(tokenAddress);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "PayGuard: caller is not the owner");
        _;
    }

    // ------------------------------------------------------------------
    // Owner: funding
    // ------------------------------------------------------------------

    /// @notice Deposit tokens into the vault. The owner must first `approve`
    ///         the vault on the token contract for at least `amount`.
    function deposit(uint256 amount) external onlyOwner {
        require(amount > 0, "PayGuard: deposit amount is zero");
        require(token.transferFrom(msg.sender, address(this), amount), "PayGuard: deposit transfer failed");
        emit Deposited(msg.sender, amount);
    }

    /// @notice Withdraw tokens back out of the vault (owner only).
    function withdraw(uint256 amount) external onlyOwner {
        require(amount > 0, "PayGuard: withdraw amount is zero");
        require(token.balanceOf(address(this)) >= amount, "PayGuard: insufficient vault balance");
        require(token.transfer(msg.sender, amount), "PayGuard: withdraw transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    // ------------------------------------------------------------------
    // Owner: session management
    // ------------------------------------------------------------------

    /// @notice Create a payment session for one agent address.
    /// @param agent The session key holder. A separate EOA, never the owner.
    /// @param perTxCap Hard ceiling per payment.
    /// @param approvalThreshold Payments above this amount (up to the cap)
    ///        queue for owner approval instead of executing. Set it equal to
    ///        `perTxCap` to disable queueing; set it to 0 to queue everything.
    /// @param sessionBudget Hard ceiling on total executed spend.
    /// @param expiry Unix timestamp at which the session dies automatically.
    /// @param allowlist Recipients the agent is allowed to pay.
    /// @return sessionId The id of the new session.
    function createSession(
        address agent,
        uint256 perTxCap,
        uint256 approvalThreshold,
        uint256 sessionBudget,
        uint256 expiry,
        address[] calldata allowlist
    ) external onlyOwner returns (uint256 sessionId) {
        require(agent != address(0), "PayGuard: agent address is zero");
        require(agent != owner, "PayGuard: agent must not be the owner");
        require(perTxCap > 0, "PayGuard: per-transaction cap is zero");
        require(approvalThreshold <= perTxCap, "PayGuard: approval threshold exceeds cap");
        require(sessionBudget >= perTxCap, "PayGuard: session budget below per-transaction cap");
        require(expiry > block.timestamp, "PayGuard: expiry is in the past");
        require(allowlist.length > 0, "PayGuard: allowlist is empty");

        sessionId = sessionCount++;
        Session storage s = _sessions[sessionId];
        s.agent = agent;
        s.perTxCap = perTxCap;
        s.approvalThreshold = approvalThreshold;
        s.sessionBudget = sessionBudget;
        s.spent = 0;
        s.expiry = expiry;
        s.revoked = false;
        s.exists = true;

        for (uint256 i = 0; i < allowlist.length; i++) {
            require(allowlist[i] != address(0), "PayGuard: allowlist contains zero address");
            _allowlist[sessionId][allowlist[i]] = true;
        }

        emit SessionCreated(sessionId, agent, perTxCap, approvalThreshold, sessionBudget, expiry);
    }

    /// @notice Revoke a session instantly. The agent can no longer pay, and
    ///         queued payments from it can no longer be approved.
    function revokeSession(uint256 sessionId) external onlyOwner {
        Session storage s = _sessions[sessionId];
        require(s.exists, "PayGuard: session does not exist");
        require(!s.revoked, "PayGuard: session already revoked");
        s.revoked = true;
        emit SessionRevoked(sessionId, s.agent);
    }

    // ------------------------------------------------------------------
    // Agent: payments
    // ------------------------------------------------------------------

    /// @notice Attempt a payment from a session. Only the session's agent may
    ///         call this. Small payments execute immediately; payments above
    ///         the session's approval threshold are queued for the owner.
    /// @return paymentId The id of the payment record (audit trail entry).
    function pay(uint256 sessionId, address to, uint256 amount) external returns (uint256 paymentId) {
        Session storage s = _sessions[sessionId];
        require(s.exists, "PayGuard: session does not exist");
        require(msg.sender == s.agent, "PayGuard: caller is not the session agent");
        require(!s.revoked, "PayGuard: session revoked");
        require(block.timestamp < s.expiry, "PayGuard: session expired");
        require(amount > 0, "PayGuard: payment amount is zero");
        require(_allowlist[sessionId][to], "PayGuard: recipient not allowlisted");
        require(amount <= s.perTxCap, "PayGuard: amount exceeds per-transaction cap");
        require(s.spent + amount <= s.sessionBudget, "PayGuard: amount exceeds session budget");

        paymentId = paymentCount++;
        Payment storage p = _payments[paymentId];
        p.sessionId = sessionId;
        p.to = to;
        p.amount = amount;

        if (amount > s.approvalThreshold) {
            // Too big to run unsupervised: queue it for a human decision.
            // Budget is only debited when (and if) the owner approves.
            p.status = PaymentStatus.Pending;
            emit PaymentQueued(paymentId, sessionId, to, amount);
        } else {
            p.status = PaymentStatus.Executed;
            _execute(s, p, paymentId);
        }
    }

    // ------------------------------------------------------------------
    // Owner: approval queue
    // ------------------------------------------------------------------

    /// @notice Approve a queued payment. It executes now, re-checking that
    ///         the session is still alive and the budget still has room.
    function approve(uint256 paymentId) external onlyOwner {
        Payment storage p = _payments[paymentId];
        require(p.status == PaymentStatus.Pending, "PayGuard: payment is not pending");
        Session storage s = _sessions[p.sessionId];
        require(!s.revoked, "PayGuard: session revoked");
        require(block.timestamp < s.expiry, "PayGuard: session expired");
        require(s.spent + p.amount <= s.sessionBudget, "PayGuard: amount exceeds session budget");

        p.status = PaymentStatus.Executed;
        emit PaymentApproved(paymentId, p.sessionId);
        _execute(s, p, paymentId);
    }

    /// @notice Reject a queued payment. No funds move; the record stays in
    ///         the audit trail as Rejected.
    function reject(uint256 paymentId) external onlyOwner {
        Payment storage p = _payments[paymentId];
        require(p.status == PaymentStatus.Pending, "PayGuard: payment is not pending");
        p.status = PaymentStatus.Rejected;
        emit PaymentRejected(paymentId, p.sessionId);
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    function _execute(Session storage s, Payment storage p, uint256 paymentId) internal {
        require(token.balanceOf(address(this)) >= p.amount, "PayGuard: insufficient vault balance");
        s.spent += p.amount;
        require(token.transfer(p.to, p.amount), "PayGuard: payment transfer failed");
        emit PaymentExecuted(paymentId, p.sessionId, p.to, p.amount);
    }

    // ------------------------------------------------------------------
    // Read functions (dashboards, audit history)
    // ------------------------------------------------------------------

    function getSession(uint256 sessionId) external view returns (Session memory) {
        require(_sessions[sessionId].exists, "PayGuard: session does not exist");
        return _sessions[sessionId];
    }

    function getPayment(uint256 paymentId) external view returns (Payment memory) {
        require(paymentId < paymentCount, "PayGuard: payment does not exist");
        return _payments[paymentId];
    }

    function isAllowlisted(uint256 sessionId, address account) external view returns (bool) {
        return _allowlist[sessionId][account];
    }

    /// @notice True if the session exists, is not revoked, and has not expired.
    function isSessionActive(uint256 sessionId) external view returns (bool) {
        Session storage s = _sessions[sessionId];
        return s.exists && !s.revoked && block.timestamp < s.expiry;
    }

    function vaultBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }
}
