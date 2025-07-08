# OAuth2/OIDC Implementation in Ruby

A comprehensive OAuth2 Authorization Server and OpenID Connect Provider implementation in Ruby 3.4, built for educational purposes using Test-Driven Development (TDD) methodology.

## Project Overview

This project demonstrates the complete OAuth2/OIDC ecosystem with three distinct components:

- **🔐 Authorization Server** (`server/`) - OAuth2 Authorization Server with OIDC Provider extensions
- **📚 Client Library** (`client/`) - OAuth2 client library for integrating with the authorization server
- **🌐 Sample RP** (`sample-rp/`) - Sample Relying Party web application demonstrating real-world usage

## Features

### OAuth2 Authorization Server
- Authorization Code Flow (RFC 6749)
- PKCE Support (RFC 7636) 
- Token Management (Access & Refresh Tokens)
- Client Registration & Validation
- Comprehensive Error Handling

### OpenID Connect Provider
- ID Token Generation & Validation
- UserInfo Endpoint
- Discovery Document (/.well-known/openid_configuration)
- JWKS Endpoint
- Standard Claims Support

### Security Features
- CSRF Protection via State Parameter
- PKCE for Enhanced Security
- Secure Token Generation
- Input Validation & Sanitization
- Timing Attack Prevention
- Comprehensive Audit Logging

## Quick Start

### Prerequisites
- Ruby 3.4.2
- Bundler

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd unwelcome
   ```

2. **Install dependencies**
   ```bash
   # Authorization Server
   cd server && bundle install

   # Client Library  
   cd ../client && bundle install

   # Sample RP
   cd ../sample-rp && bundle install
   ```

### Running the Application

1. **Start the Authorization Server**
   ```bash
   cd server
   bundle exec rackup
   # Server starts on http://localhost:9292
   ```

2. **Start the Sample RP** (in a new terminal)
   ```bash
   cd sample-rp
   bundle exec rackup
   # Sample app starts on http://localhost:4567
   ```

3. **Try the OAuth2 Flow**
   - Visit http://localhost:4567
   - Click "Login with OAuth2"
   - Complete the authorization flow
   - View your profile information

## Test-Driven Development

This project follows **t-wada TDD methodology** with a comprehensive test suite of **25 tests** covering all OAuth2/OIDC flows.

### Running Tests

```bash
# Server tests (12 tests)
cd server
bundle exec rspec

# Client library tests (6 tests)  
cd client
bundle exec rspec

# Sample RP tests (4 tests)
cd sample-rp
bundle exec rspec

# Integration tests (3 tests)
bundle exec rspec spec/integration/
```

### Test Implementation Order

The tests are designed to be implemented in a specific order following TDD best practices:

#### Phase 1: Server Foundation (12 tests)
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

#### Phase 2: Client Library (6 tests)
13. PKCE client - code_verifier/code_challenge generation
14. Authorization URL - Auth URL generation
15. Token exchange - Authorization code to token
16. Token management - Token storage/refresh
17. OIDC client - ID token validation
18. UserInfo request - User info retrieval

#### Phase 3: Sample RP (4 tests)
19. Login page - Login button and redirect
20. Callback handling - Authorization code processing
21. Profile display - User info display
22. Logout - Session cleanup

#### Phase 4: Integration (3 tests)
23. End-to-end flow - Complete auth flow
24. Error handling - Error cases
25. Security validation - Security checks

## Project Structure

```
unwelcome/
├── server/                 # OAuth2 Authorization Server + OIDC Provider
│   ├── lib/
│   │   ├── oauth2/         # OAuth2 core functionality
│   │   ├── oidc/           # OpenID Connect extensions
│   │   └── utils/          # Shared utilities
│   ├── spec/               # Server tests
│   ├── config.ru           # Rack application
│   └── Gemfile
├── client/                 # OAuth2 Client Library
│   ├── lib/
│   │   ├── oauth2_client/  # Client implementations
│   │   └── utils/          # Client utilities
│   ├── spec/               # Client tests
│   └── Gemfile
├── sample-rp/              # Sample Relying Party
│   ├── app.rb              # Sinatra web application
│   ├── views/              # HTML templates
│   ├── spec/               # RP tests
│   └── Gemfile
├── spec/
│   └── integration/        # End-to-end tests
├── CLAUDE.md               # Development guidelines
└── README.md
```

## Standards Compliance

This implementation follows established RFC standards:

- **RFC 6749** - The OAuth 2.0 Authorization Framework
- **RFC 7636** - Proof Key for Code Exchange (PKCE)
- **OpenID Connect Core 1.0** - OpenID Connect specification
- **OpenID Connect Discovery 1.0** - Discovery specification

## Development Workflow

### TDD Red-Green-Refactor Cycle

1. **🔴 Red**: Write a failing test first
2. **🟢 Green**: Write minimal code to make test pass  
3. **🔵 Refactor**: Improve code while keeping tests green

### Example TDD Workflow

```bash
# 1. Run test to see it fail (Red)
cd server
bundle exec rspec spec/utils/jwt_handler_spec.rb

# 2. Implement minimal code to pass (Green)
# Edit lib/utils/jwt_handler.rb

# 3. Run test to see it pass
bundle exec rspec spec/utils/jwt_handler_spec.rb

# 4. Refactor code while maintaining green tests
# Improve implementation, run tests frequently
```

## Security Considerations

### Implemented Security Measures

- **PKCE (Proof Key for Code Exchange)** - Prevents authorization code interception
- **State Parameter Validation** - CSRF protection for OAuth2 flows
- **Secure Token Generation** - Cryptographically secure random tokens
- **Input Validation** - All parameters validated and sanitized
- **Timing Attack Prevention** - Constant-time string comparisons
- **Rate Limiting** - Protection against brute force attacks
- **Security Headers** - Comprehensive HTTP security headers

### Security Best Practices

- All sensitive operations are logged for audit purposes
- Tokens have appropriate expiration times
- Refresh tokens are invalidated after use
- Client credentials are validated using secure methods
- All error responses include correlation IDs for debugging

## Learning Resources

This project serves as a practical learning tool for:

- **OAuth2 Protocol** - Understanding authorization flows
- **OpenID Connect** - Identity layer on top of OAuth2
- **Security Best Practices** - Web application security
- **Test-Driven Development** - TDD methodology and benefits
- **Ruby Web Development** - Sinatra, Rack, and Ruby patterns

## Configuration

### Environment Variables

```bash
# Authorization Server
OAUTH2_ISSUER=http://localhost:9292
JWT_SECRET_KEY=your-secret-key-here

# Sample RP
OAUTH2_CLIENT_ID=sample_rp_client
OAUTH2_CLIENT_SECRET=sample_rp_secret
OAUTH2_AUTHORIZATION_SERVER=http://localhost:9292
```

### Development vs Production

- **Development**: Uses in-memory storage, simplified configuration
- **Production**: Would require persistent storage (Redis/Database), proper key management

## Contributing

This is an educational project. When contributing:

1. Follow the established TDD workflow
2. Ensure all tests pass before submitting
3. Add tests for new functionality
4. Follow Ruby style guidelines
5. Update documentation as needed

## License

This project is intended for educational purposes. Please refer to the license file for usage terms.

---

**Note**: This implementation is designed for learning and demonstration purposes. For production use, additional considerations around scalability, persistence, and enterprise security would be required.
