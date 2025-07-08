# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an OAuth2/OIDC implementation project written in Ruby 3.4 for learning purposes. The project is structured as three separate components:

- **server/**: OAuth2 Authorization Server + OIDC Provider
- **client/**: OAuth2 Client library
- **sample-rp/**: Sample Relying Party (test web application)

## Development Commands

### Server (OAuth2 Authorization Server)
```bash
cd server
bundle install
bundle exec rspec                    # Run all tests
bundle exec rspec spec/oauth2/       # Run OAuth2 tests only
bundle exec rspec spec/oidc/         # Run OIDC tests only
bundle exec rackup                   # Start server on port 9292
```

### Client (OAuth2 Client Library)
```bash
cd client
bundle install
bundle exec rspec                    # Run all tests
bundle exec rspec spec/oauth2_client/ # Run client tests
```

### Sample RP (Relying Party)
```bash
cd sample-rp
bundle install
bundle exec rspec                    # Run all tests
bundle exec rackup                   # Start sample app on port 9292
```

## TDD Workflow

This project follows t-wada TDD methodology with Red-Green-Refactor cycle:

1. **Red**: Write a failing test first
2. **Green**: Write minimal code to make test pass
3. **Refactor**: Improve code while keeping tests green

### Test Implementation Order

**Phase 1: Server Foundation (12 tests)**
1. JWT utilities - JWT generation/verification
2. Crypto utilities - Secure random string generation
3. Client registry - Client registration/lookup
4. Authorization code - Code generation/validation
5. Authorization endpoint - GET /authorize
6. Token endpoint - POST /token
7. Access token - Token generation/validation
8. Refresh token - Token refresh flow
9. ID token - OIDC ID token generation
10. UserInfo endpoint - GET /userinfo
11. OIDC Discovery - /.well-known/openid_configuration
12. PKCE support - Server-side PKCE validation

**Phase 2: Client Library (6 tests)**
13. PKCE client - code_verifier/code_challenge generation
14. Authorization URL - Auth URL generation
15. Token exchange - Authorization code to token
16. Token management - Token storage/refresh
17. OIDC client - ID token validation
18. UserInfo request - User info retrieval

**Phase 3: Sample RP (4 tests)**
19. Login page - Login button and redirect
20. Callback handling - Authorization code processing
21. Profile display - User info display
22. Logout - Session cleanup

**Phase 4: Integration (3 tests)**
23. End-to-end flow - Complete auth flow
24. Error handling - Error cases
25. Security validation - Security checks

## Architecture Overview

### Server Components
- `OAuth2::AuthorizationServer` - Handles authorization requests
- `OAuth2::TokenManager` - Manages token lifecycle
- `OAuth2::ClientRegistry` - Client registration and validation
- `OIDC::Provider` - OpenID Connect extensions
- `OIDC::IDToken` - ID token generation/validation
- `Utils::JWTHandler` - JWT operations
- `Utils::CryptoUtils` - Cryptographic utilities

### Client Components
- `OAuth2Client::AuthorizationCodeFlow` - Authorization code flow
- `OAuth2Client::TokenManager` - Token management
- `OAuth2Client::OIDCClient` - OIDC client functionality
- `Utils::PKCE` - PKCE implementation

### Security Considerations
- Use PKCE (Proof Key for Code Exchange) for all flows
- Validate all redirect URIs against registered clients
- Implement proper token expiration and refresh
- Use secure random generation for codes and tokens
- Validate JWT signatures and claims
- Implement proper CORS headers for cross-origin requests

## OAuth2/OIDC Standards Compliance

This implementation follows:
- RFC 6749 - The OAuth 2.0 Authorization Framework
- RFC 7636 - Proof Key for Code Exchange (PKCE)
- OpenID Connect Core 1.0
- OpenID Connect Discovery 1.0

## Test Structure

Each test should:
1. Be independent and isolated
2. Follow Given-When-Then pattern
3. Test one specific behavior
4. Use descriptive test names
5. Include both positive and negative cases

## Common Development Patterns

### Error Handling
- Use custom exception classes for different error types
- Return proper HTTP status codes
- Include error descriptions in responses
- Log security-relevant events

### Configuration
- Use environment variables for sensitive data
- Provide sensible defaults for development
- Document all configuration options

### Testing
- Mock external dependencies
- Use factories for test data
- Test edge cases and error conditions
- Verify security properties