---
stepsCompleted: [1, 2, 3, 4, 7, 8, 9, 10, 11]
inputDocuments: []
documentCounts:
  briefs: 0
  research: 0
  brainstorming: 0
  projectDocs: 0
workflowType: 'prd'
lastStep: 11
project_name: 'Headsup'
user_name: 'Riddler'
date: '2025-12-12T22:00:34+08:00'
---

# Product Requirements Document - Headsup

**Author:** Riddler
**Date:** 2025-12-12T22:00:34+08:00

## Executive Summary

**Headsup** is a backend-first poker server designed to host reliable heads-up No Limit Hold'em (NLHE) games. This is a **foundation project** - an MVP focused on building robust, well-tested game logic and server infrastructure that can support future expansion.

The system provides core poker server functionality including player authentication (simple username/password signup), lobby management for browsing available tables, and complete heads-up NLHE game mechanics. As a play-money platform, the focus is on reliability and correctness of game state management, fair card dealing, and multiplayer coordination without the complexity of real-money compliance.

The backend-first approach prioritizes thorough testing and validation of server functionality before adding frontend interfaces. This ensures the foundation is solid and trustworthy - critical for any poker platform where players need confidence in game fairness and state consistency.

### What Makes This Special

**Headsup** takes a **reliability-first, foundation-first** approach to building a poker server. Rather than rushing to a full-featured product, this project focuses on:

- **Correctness over features**: Building a rock-solid game engine that handles all edge cases correctly
- **Testing as a first-class concern**: Backend-only MVP enables comprehensive automated testing without UI complexity
- **Foundation for growth**: Clean, reliable core that can support future features, game variants, or enhanced experiences
- **Play-money simplicity**: Removing regulatory complexity allows focus on game mechanics and player experience

If this succeeds, developers and poker enthusiasts will have a **trustworthy, well-tested poker server foundation** they can build upon, extend, or deploy for their own communities.

## Project Classification

**Technical Type:** api_backend  
**Domain:** gaming  
**Complexity:** medium  
**Project Context:** Greenfield - new project

This is a backend API server project in the gaming domain with medium complexity. Key technical concerns include:

- Real-time multiplayer game state management
- Fair and verifiable card shuffling/dealing algorithms
- Concurrent player actions and turn-based coordination
- Session and authentication management
- Lobby and table matchmaking logic

The gaming domain combined with the backend architecture suggests focus on:
- Robust game logic with comprehensive edge case handling
- State machine design for game flow (betting rounds, showdown, hand resolution)
- Testing strategies for non-deterministic game scenarios
- Performance for real-time player interactions

## Success Criteria

### User Success

Success for **Headsup** means delivering a foundation that developers (including future you) can trust and build upon:

- **State Integrity:** The game state machine never enters invalid states, even with malicious or malformed player actions. All state transitions are validated with assertions and invariants.
- **Comprehensive Testing:** The test suite catches edge cases that weren't explicitly anticipated through property-based testing, fuzz testing, and exhaustive scenario coverage.
- **Developer Confidence:** When integrating this server into a larger system or extending it with new features, developers can rely on the core game logic without worrying about hidden bugs or edge cases.

### Business Success

As a foundation project, business success is measured by **project completion and future-readiness**:

- **MVP Completion:** A reliable, well-tested heads-up NLHE poker server with play money support
- **Security Confidence:** Server successfully handles malicious players and network problems gracefully without compromising game integrity
- **Foundation Quality:** The codebase is stable and robust enough to support future ambitious features (real money, mental poker protocol)
- **Time to Value:** Future feature development is accelerated because the foundation handles all the complex poker logic correctly

### Technical Success

The server must meet high standards for security and resilience:

**Security:**
- Server-side validation prevents all forms of cheating (clients cannot manipulate game state)
- Authentication and session management prevent unauthorized access and impersonation
- Input validation prevents injection attacks and malformed messages
- All game-critical logic runs server-side with zero trust in client data

**Malicious Player Handling:**
- Rate limiting prevents flood attacks and denial of service
- Invalid actions are rejected gracefully without crashing or corrupting state
- Timeout mechanisms prevent players from stalling games indefinitely
- Server validates all player actions against current game state

**Network Resilience:**
- Graceful handling of player disconnections with reconnection support
- Message delivery guarantees for critical game actions
- State recovery after network interruptions
- Proper handling of partial connections (one player connected, one disconnected)

### Measurable Outcomes

Success is achieved when:

- **Stability Confidence:** Extended testing (property-based, fuzz, scenario) produces zero state corruption or crash bugs
- **Game Logic Correctness:** All poker rules, edge cases, and hand evaluation work correctly across thousands of simulated games
- **Security Validation:** Penetration testing and malicious player simulations show no exploitable vulnerabilities
- **Foundation Readiness:** Codebase quality and test coverage give high confidence for building advanced features (mental poker) on top

## Product Scope

### MVP - Minimum Viable Product

The foundation focuses on **play money games** with traditional server-based card dealing:

**Core Features:**
- Heads-up No Limit Hold'em game mechanics (complete and correct)
- Player authentication (username/password signup)
- Lobby system for browsing and joining tables
- Complete betting rounds with all edge cases (all-in, side pots, etc.)
- Hand evaluation and winner determination
- Chip/stack management for play money
- Disconnection and reconnection handling
- Robust state machine with validation

**Technical Requirements:**
- Server-side validation and security
- Comprehensive test suite (unit, integration, property-based)
- Network resilience (graceful degradation, recovery)
- Backend API only (no frontend UI in MVP)

### Growth Features (Post-MVP)

**Real Money Support:**
- Payment processing integration
- Regulatory compliance (varies by jurisdiction)
- Enhanced security and audit logging
- Financial transaction handling

### Vision (Future)

**Mental Poker Protocol:**
- Cryptographic card dealing without trusted server
- Zero-knowledge proofs for game fairness
- Decentralized game state verification
- Provably fair shuffling and dealing

This represents the long-term vision - a groundbreaking poker server where players don't need to trust the server for fair dealing.

## User Journeys

### Journey 1: Alex Chen - Mastering the Mental Game

Alex discovered poker during college but always struggled with heads-up play - the intense one-on-one pressure felt completely different from full-table games. After watching professional heads-up matches online, Alex became fascinated by the psychology and strategy, but every time they tried to practice on existing poker sites, the stakes (even the "micro" stakes) made them too nervous to experiment with aggressive strategies they'd been studying.

Late one evening, after watching another tutorial on heads-up ranges and 3-bet frequencies, Alex decides they need a safe practice environment. They discover **Headsup** - a play-money server designed for serious practice. Alex creates an account with just a username and password, takes a moment to browse the lobby showing available tables, and joins their first heads-up game.

The first few hands are tentative. Alex tries a loose 3-bet from the button, gets called, and has to navigate post-flop - exactly the scenario they'd been afraid to practice with real money. When their opponent disconnects briefly mid-hand, Alex worries the game will crash, but the server handles it gracefully, pausing the action and giving the opponent time to reconnect. The hand completes perfectly.

Over the next few weeks, Alex plays hundreds of hands, experimenting with different strategies without the fear of losing rent money. They try hyper-aggressive approaches, balanced ranges, exploitative adjustments - learning which strategies actually work under pressure. When they finally return to real-money games three months later, their heads-up win rate has tripled. They've learned that **Headsup** gave them exactly what they needed: a reliable, judgment-free practice environment where the only thing at stake was their pride.

### Journey 2: Jordan Rivera - Keeping the Games Running

Jordan manages a small online gaming community and recently deployed **Headsup** to give members a place to play poker together. As the system operator, Jordan's main concern is simple: **keep the games running smoothly** so players trust the platform.

On the first weekend after launch, everything seems fine until Jordan notices something odd in the logs - a player appears to be sending malformed game actions, possibly trying to exploit the server. Jordan watches nervously, but the server handles it perfectly: invalid actions are rejected, the malicious player is rate-limited, and the game state never corrupts. Jordan breathes a sigh of relief.

The real test comes during a busy Friday night. Twenty concurrent games are running when Jordan notices network latency spiking. Several players disconnect simultaneously. Jordan's heart races - "Is this going to crash everything?" But the server's resilience design kicks in: disconnected players are given time to reconnect, games pause gracefully, and when players come back online, they resume exactly where they left off. No chips lost, no corrupted state, no angry messages in the community Discord.

Three months later, Jordan's community has grown from 20 to 150 active players. The server has handled thousands of games, hundreds of disconnections, and several attempted exploits - all without a single critical failure. Jordan realizes that the foundation's focus on **reliability and security** means they can sleep soundly instead of worrying about the next server crisis. Players trust the platform, and Jordan trusts the server. That's exactly what was needed.

### Journey Requirements Summary

The user journeys reveal critical capabilities needed for **Headsup**:

**From Alex's Player Journey:**
- Simple user authentication (username/password signup)
- Lobby system for browsing and joining available tables
- Complete heads-up NLHE poker mechanics (betting, hand evaluation, pot management)
- Disconnection/reconnection handling that preserves game state
- State persistence and recovery across network interruptions
- Smooth, reliable game flow without crashes or corruption

**From Jordan's Operator Journey:**
- Server-side security validation that rejects malformed actions
- Rate limiting and malicious player detection/prevention
- Support for concurrent games (multiple tables simultaneously)
- Network resilience with graceful degradation
- Logging and monitoring capabilities for system oversight
- State integrity guarantees under all failure conditions
- Automated recovery mechanisms that don't require operator intervention

## Backend Server Specific Requirements

### Project-Type Overview

**Headsup** is a WebSocket-based backend server that provides real-time multiplayer poker gameplay. The architecture prioritizes simplicity and reliability for the MVP foundation, using proven technologies (WebSockets, JSON, session-based auth) rather than adding complexity through versioning or client SDKs.

This backend-only approach allows comprehensive testing of game logic and server resilience before frontend development, ensuring the foundation is rock-solid.

### Communication Protocol

**WebSocket-Based Architecture:**
- All client-server communication uses WebSockets for real-time bidirectional messaging
- Persistent connections maintained for active players
- WebSocket handles authentication, lobby operations, and gameplay
- JSON message format for all communications

**Connection Lifecycle:**
1. Client connects via WebSocket
2. Client sends authentication message with session token
3. Server validates token and associates connection with player identity
4. Bidirectional messaging for all subsequent operations (lobby, game actions, state updates)
5. Graceful disconnection handling with reconnection support

### Authentication Model

**Session-Based Authentication:**
- **Signup/Login:** Username and password authentication creates server-side session
- **Session Token:** Server generates and returns session token upon successful authentication
- **WebSocket Authentication:** Client sends session token in initial WebSocket message
- **Session Management:** Server maintains session state (in-memory or database-backed)
- **Session Validation:** All WebSocket connections validated against active sessions
- **Logout/Invalidation:** Sessions can be explicitly invalidated on logout or timeout

**Security Considerations:**
- Session tokens must be cryptographically secure (e.g., random 256-bit tokens)
- Sessions expire after inactivity period
- Password storage uses secure hashing (e.g., bcrypt, argon2)
- Server-side validation prevents session hijacking or replay attacks

### Data Schemas

**JSON Message Format:**
All messages between client and server use JSON with defined schemas:

**Message Structure:**
```json
{
  "type": "message_type",
  "payload": { /* type-specific data */ },
  "timestamp": "ISO 8601 timestamp"
}
```

**Key Message Categories:**
- **Authentication:** Login, signup, session validation
- **Lobby:** List tables, join table, leave table
- **Game Actions:** Fold, call, raise, check, all-in
- **Game State:** Hand dealt, betting round, showdown, winner
- **Player State:** Chip counts, position, connection status

All game-critical messages include validation fields to prevent tampering or desynchronization.

### Rate Limiting & Security

**Request Rate Limiting:**
- **Per-Connection Limits:** Maximum requests per second per WebSocket connection
- **Action Limits:** Game actions throttled to prevent spam (e.g., can't send 100 raises per second)
- **Connection Limits:** Maximum concurrent connections per player (prevent multi-connection attacks)
- **Burst Protection:** Short-term burst allowance with long-term rate enforcement

**Malicious Player Protection:**
- Invalid messages rejected gracefully (connection not terminated unless repeated violations)
- Malformed JSON or invalid game actions logged and rate-limited
- Timeout mechanisms prevent players from stalling games indefinitely
- Automated detection and temporary banning of abusive behavior patterns

### API Versioning & Evolution

**No Versioning for MVP:**
- Single protocol version for foundation
- Clients expected to upgrade synchronously with server updates
- Simplifies development and testing for controlled deployment
- Future consideration: Add versioning when third-party clients are supported

**Protocol Evolution Strategy:**
- Breaking changes documented clearly
- Staged rollouts for major protocol changes
- Clients and server upgraded together during MVP phase

### Client Integration

**No SDK Provided:**
- Protocol documented with message schemas and examples
- Clients (built later) will use standard WebSocket libraries
- JSON schemas serve as integration contract
- Focus on clean, well-documented protocol rather than SDK overhead

### Error Handling

**Error Response Format:**
```json
{
  "type": "error",
  "error_code": "INVALID_ACTION",
  "message": "Human-readable error description",
  "details": { /* context-specific error details */ }
}
```

**Error Categories:**
- Authentication errors (invalid credentials, expired session)
- Game logic errors (invalid action, out of turn)
- Network errors (connection lost, timeout)
- Server errors (internal failure, rate limit exceeded)

### Implementation Considerations

**Technology Stack Implications:**
- WebSocket library/framework selection (e.g., ws, socket.io, native WebSocket APIs)
- Session storage backend (in-memory for MVP, database for persistence)
- JSON parsing/validation for all messages
- Concurrent connection handling (async/event-driven architecture)

**Performance Targets:**
- Sub-100ms message round-trip latency for game actions
- Support for 20+ concurrent games (MVP target based on Jordan's operator journey)
- Graceful degradation under load (reject new connections rather than crash)

- Malicious player simulation tests for security validation

## Project Scoping & Phased Development

### MVP Strategy & Philosophy

**MVP Approach:** Platform MVP - Foundation First

**Headsup** follows a **platform MVP** strategy focused on building a reliable, well-tested foundation that can support ambitious future features. Rather than rushing to feature completeness, the MVP prioritizes correctness, security, and robustness in core poker server functionality.

This approach recognizes that reliability is non-negotiable for a poker server - players must trust the game state, operators must trust the server won't corrupt data, and future development must trust the foundation won't require rewrites.

**Resource Requirements:**
- Backend engineering expertise (server architecture, WebSockets, game logic)
- Quality assurance focus (property-based testing, fuzz testing, security testing)
- Poker domain knowledge (NLHE rules, edge cases, tournament structures)
- DevOps for deployment and monitoring

### MVP Feature Set (Phase 1)

**Core User Journeys Supported:**
- **Player Journey (Alex):** Practice heads-up NLHE strategy in safe play-money environment
- **Operator Journey (Jordan):** Manage reliable poker server with graceful failure handling

**Must-Have Capabilities:**

**Game Mechanics:**
- Complete heads-up No Limit Hold'em implementation
- All betting rounds (pre-flop, flop, turn, river)
- Hand evaluation and winner determination
- Pot management including side pots and all-in scenarios
- Robust state machine with validated transitions

**Player Management:**
- Username/password authentication
- Session-based auth with secure token generation
- Play money chip stacks and management
- Player state tracking (chips, position, connection status)

**Lobby & Table Management:**
- Lobby system for browsing available tables
- Join/leave table functionality
- Support for multiple concurrent tables (20+ target)

**Network Resilience:**
- WebSocket-based real-time communication
- Graceful disconnection handling
- Reconnection support with state recovery
- Timeout mechanisms for stalled games

**Security & Reliability:**
- Server-side validation of all game actions
- Rate limiting to prevent abuse
- Malicious player detection and mitigation
- State integrity guarantees under all conditions

**Testing Infrastructure:**
- Comprehensive test suite (unit, integration, property-based)
- Fuzz testing for edge case discovery
- Security validation and penetration testing
- Backend-only architecture enables thorough testing without UI complexity

### Post-MVP Features

**Phase 2: Real Money Support**
- Payment processing integration
- Regulatory compliance (jurisdiction-dependent)
- Enhanced security and audit logging
- Financial transaction handling
- KYC/AML compliance
- Enhanced fraud detection

**Phase 3: Mental Poker Protocol**
- Cryptographic card dealing without trusted server
- Zero-knowledge proofs for game fairness
- Decentralized game state verification
- Provably fair shuffling and dealing
- Blockchain or distributed ledger integration
- Novel trust model for online poker

**Additional Future Features:**
- Frontend client development (web, mobile)
- Additional game variants (Omaha, tournaments)
- Multi-table support for players
- Spectator mode
- Hand history and statistics
- Social features and friend lists

### Risk Mitigation Strategy

**Technical Risks:**
- **Risk:** Complex poker game logic with numerous edge cases
- **Mitigation:** Backend-first approach enables exhaustive testing; property-based testing discovers unexpected edge cases; phased development allows validation before adding complexity

**Market Risks:**
- **Risk:** Many existing poker platforms already exist
- **Mitigation:** MVP is a foundation project, not a market launch; play-money focus removes regulatory barriers; future mental poker innovation provides long-term differentiation

**Resource Risks:**
- **Risk:** Implementing robust, secure poker server requires significant effort
- **Mitigation:** Focused MVP scope (heads-up only, play money only, no frontend); comprehensive testing prevents costly rewrites; foundation-first approach means future development builds on solid base

- **Mitigation:** Clear MVP boundaries documented in PRD; "foundation first" philosophy keeps focus on reliability over features; post-MVP roadmap captures future ideas without diluting MVP

## Functional Requirements

### User Account Management

- FR1: Users can create an account with username and password
- FR2: Users can log in with their credentials to receive a session token
- FR3: Users can log out, invalidating their session
- FR4: The system maintains session state for authenticated users
- FR5: Users have a play money chip balance associated with their account

### Lobby & Table Discovery

- FR6: Users can view a list of available heads-up poker tables
- FR7: Users can see table information (stakes, players, game status)
- FR8: Users can join an available table
- FR9: Users can leave a table they are seated at
- FR10: The system supports multiple concurrent tables running simultaneously

### Poker Game Mechanics

- FR11: The system deals a complete heads-up No Limit Hold'em game
- FR12: Players receive two hole cards at the start of each hand
- FR13: The system deals community cards (flop, turn, river) at appropriate times
- FR14: Players can perform betting actions (fold, check, call, raise, all-in)
- FR15: The system enforces valid betting actions based on game state
- FR16: The system manages betting rounds (pre-flop, flop, turn, river)
- FR17: The system calculates pot size including side pots for all-in scenarios
- FR18: The system evaluates poker hands at showdown to determine winners
- FR19: The system awards chips to winning players
- FR20: The system manages player chip stacks throughout the game

### Network Resilience & Session Management

- FR21: The system detects when a player disconnects during a game
- FR22: Players can reconnect to an in-progress game after disconnection
- FR23: The system preserves game state during player disconnections
- FR24: The system implements timeout mechanisms for inactive players
- FR25: The system handles partial connections (one player connected, one disconnected)

### Security & Validation

- FR26: The system validates all player actions server-side before executing them
- FR27: The system rejects invalid or malformed game actions
- FR28: The system enforces rate limiting on player actions
- FR29: The system prevents multiple concurrent connections from the same player account
- FR30: The system logs suspicious behavior patterns for review

### Game State Management

- FR31: The system maintains authoritative game state on the server
- FR32: The system broadcasts game state updates to connected players
- FR33: The system ensures game state transitions follow poker rules
- FR34: The system prevents invalid state transitions
- FR35: The system guarantees state integrity under all conditions (disconnections, errors, malicious actions)

### Communication Protocol

- FR39: The system returns appropriate error messages for invalid requests

## Non-Functional Requirements

### Performance

**Response Time:**
- NFR1: Game actions (fold, call, raise) complete with sub-100ms server-side processing time
- NFR2: WebSocket message round-trip latency stays below 100ms under normal network conditions
- NFR3: Lobby operations (list tables, join table) complete within 1 second

**Throughput:**
- NFR4: Server supports minimum 20 concurrent poker games without performance degradation
- NFR5: Server handles game state updates and broadcasts to all active players within 50ms

**Scalability:**
- NFR6: System gracefully degrades under load by rejecting new connections rather than crashing
- NFR7: Server maintains performance targets up to configured capacity limits

### Security

**Authentication & Authorization:**
- NFR8: Session tokens use cryptographically secure random generation (minimum 256-bit entropy)
- NFR9: Passwords stored using secure hashing algorithms (bcrypt, argon2, or equivalent)
- NFR10: Session tokens expire after configurable inactivity period
- NFR11: All authentication attempts logged for security monitoring

**Data Protection:**
- NFR12: All game-critical logic executes server-side with zero trust in client data
- NFR13: Server validates all incoming messages for structure, content, and game legality
- NFR14: Session hijacking prevented through secure token management and validation

**Abuse Prevention:**
- NFR15: Rate limiting enforces maximum requests per second per connection
- NFR16: Malformed or invalid actions rejected without terminating connection (unless repeated violations)
- NFR17: Suspicious behavior patterns logged and flagged for review
- NFR18: Multiple concurrent connections from same account prevented

### Reliability

**Availability:**
- NFR19: Server handles player disconnections gracefully without corrupting game state
- NFR20: Players can reconnect to in-progress games after network interruption
- NFR21: Game state persisted across disconnections to enable recovery

**State Integrity:**
- NFR22: All game state transitions validated against poker rules before execution
- NFR23: Invalid state transitions prevented through state machine design
- NFR24: Zero state corruption tolerance - property-based testing validates state integrity across random scenarios
- NFR25: Game state remains consistent under all conditions (disconnections, errors, malicious actions)

**Error Handling:**
- NFR26: All errors return structured error messages with error codes and descriptions
- NFR27: Server continues operating normally when individual games encounter errors
- NFR28: Errors logged with sufficient detail for debugging and monitoring

**Testability:**
- NFR29: Comprehensive test suite achieves high coverage of game logic and edge cases
- NFR30: Property-based tests validate game logic across thousands of random scenarios
- NFR31: Fuzz testing discovers edge cases not explicitly anticipated
- NFR32: Security validation includes penetration testing and malicious player simulation

### Maintainability

**Code Quality:**
- NFR33: Code follows consistent style and naming conventions
- NFR34: Critical game logic includes comprehensive inline documentation
- NFR35: State machine design enables reasoning about valid transitions

**Monitoring & Observability:**
- NFR36: Server logs critical events (authentication, game actions, errors, security events)
- NFR37: Logging provides sufficient detail for debugging production issues
- NFR38: System provides visibility into concurrent game count and connection status
