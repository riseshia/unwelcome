require 'spec_helper'
require 'rack/test'

RSpec.describe 'OAuth2/OIDC Security Validation', type: :integration do
  include Rack::Test::Methods
  
  describe 'CSRF Protection' do
    it 'validates state parameter in authorization flow' do
      # Test 25: Security validation - Security checks
      
      # Step 1: Initiate authorization with state parameter
      stored_state = 'secure_random_state_value'
      session = { oauth_state: stored_state }
      
      # Step 2: Authorization server should include same state in callback
      valid_callback_url = "/callback?code=auth_code&state=#{stored_state}"
      invalid_callback_url = "/callback?code=auth_code&state=different_state"
      
      # Valid state should succeed (after token exchange)
      get valid_callback_url, {}, { 'rack.session' => session }
      expect(last_response.status).not_to eq(400)
      
      # Invalid state should fail
      get invalid_callback_url, {}, { 'rack.session' => session }
      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('Invalid state parameter')
    end
    
    it 'requires state parameter when configured' do
      # Missing state parameter should be rejected
      get '/callback?code=auth_code'
      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('Missing state parameter')
    end
    
    it 'generates cryptographically secure state values' do
      state_values = []
      
      # Generate multiple state values
      10.times do
        visit '/login'
        state_values << last_request.session[:oauth_state]
      end
      
      # All should be unique
      expect(state_values.uniq.length).to eq(10)
      
      # All should be sufficiently long and random
      state_values.each do |state|
        expect(state.length).to be >= 32
        expect(state).to match(/\A[a-zA-Z0-9_-]+\z/)
      end
    end
  end
  
  describe 'PKCE Security' do
    it 'enforces PKCE when client uses code_challenge' do
      # If authorization request included code_challenge, 
      # token request MUST include code_verifier
      
      post '/token', {
        grant_type: 'authorization_code',
        code: 'code_issued_with_pkce',
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback'
        # Missing code_verifier
      }
      
      expect(last_response.status).to eq(400)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_grant')
      expect(response['error_description']).to include('code_verifier required')
    end
    
    it 'validates code_verifier format' do
      # code_verifier must be 43-128 characters, URL-safe
      invalid_verifiers = [
        'too_short',                    # Too short
        'a' * 129,                     # Too long
        'invalid characters!@#$%'      # Invalid characters
      ]
      
      invalid_verifiers.each do |verifier|
        post '/token', {
          grant_type: 'authorization_code',
          code: 'code_issued_with_pkce',
          client_id: 'test_client',
          client_secret: 'test_secret',
          redirect_uri: 'http://localhost:3000/callback',
          code_verifier: verifier
        }
        
        expect(last_response.status).to eq(400)
        response = JSON.parse(last_response.body)
        expect(response['error']).to eq('invalid_grant')
      end
    end
    
    it 'correctly validates S256 code challenge' do
      # Known PKCE test vectors
      code_verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      expected_challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
      
      # Mock authorization code issued with this challenge
      post '/token', {
        grant_type: 'authorization_code',
        code: 'code_with_known_challenge',
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback',
        code_verifier: code_verifier
      }
      
      # Should succeed with correct verifier
      expect(last_response.status).to eq(200)
      
      # Should fail with incorrect verifier
      post '/token', {
        grant_type: 'authorization_code',
        code: 'code_with_known_challenge',
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback',
        code_verifier: 'wrong_verifier'
      }
      
      expect(last_response.status).to eq(400)
    end
  end
  
  describe 'Token Security' do
    it 'generates cryptographically secure tokens' do
      tokens = []
      
      # Generate multiple access tokens
      10.times do
        post '/token', {
          grant_type: 'authorization_code',
          code: "valid_code_#{rand(1000)}",
          client_id: 'test_client',
          client_secret: 'test_secret',
          redirect_uri: 'http://localhost:3000/callback'
        }
        
        if last_response.status == 200
          response = JSON.parse(last_response.body)
          tokens << response['access_token']
        end
      end
      
      # All tokens should be unique
      expect(tokens.uniq.length).to eq(tokens.length)
      
      # Tokens should be sufficiently long and random
      tokens.each do |token|
        expect(token.length).to be >= 32
        expect(token).not_to include(' ')  # No spaces
      end
    end
    
    it 'sets appropriate token expiration times' do
      post '/token', {
        grant_type: 'authorization_code',
        code: 'valid_code',
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
      
      expect(last_response.status).to eq(200)
      response = JSON.parse(last_response.body)
      
      # Access token should have reasonable expiration
      expect(response['expires_in']).to be_between(300, 7200)  # 5 minutes to 2 hours
      
      # Token type should be Bearer
      expect(response['token_type']).to eq('Bearer')
    end
    
    it 'properly invalidates refresh tokens after use' do
      refresh_token = 'valid_refresh_token'
      
      # First use should succeed
      post '/token', {
        grant_type: 'refresh_token',
        refresh_token: refresh_token,
        client_id: 'test_client',
        client_secret: 'test_secret'
      }
      expect(last_response.status).to eq(200)
      
      # Second use of same refresh token should fail
      post '/token', {
        grant_type: 'refresh_token',
        refresh_token: refresh_token,
        client_id: 'test_client',
        client_secret: 'test_secret'
      }
      expect(last_response.status).to eq(400)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_grant')
    end
  end
  
  describe 'Client Authentication Security' do
    it 'supports client_secret_basic authentication' do
      # HTTP Basic authentication for client credentials
      basic_auth = Base64.strict_encode64('test_client:test_secret')
      
      header 'Authorization', "Basic #{basic_auth}"
      post '/token', {
        grant_type: 'authorization_code',
        code: 'valid_code',
        redirect_uri: 'http://localhost:3000/callback'
      }
      
      expect(last_response.status).to eq(200)
    end
    
    it 'supports client_secret_post authentication' do
      # Client credentials in POST body
      post '/token', {
        grant_type: 'authorization_code',
        code: 'valid_code',
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
      
      expect(last_response.status).to eq(200)
    end
    
    it 'prevents client credential brute force attacks' do
      # Multiple failed attempts should trigger rate limiting
      10.times do
        post '/token', {
          grant_type: 'authorization_code',
          code: 'valid_code',
          client_id: 'test_client',
          client_secret: 'wrong_secret',
          redirect_uri: 'http://localhost:3000/callback'
        }
      end
      
      # Should eventually return rate limit error
      expect(last_response.status).to eq(429)
      expect(last_response.headers).to have_key('Retry-After')
    end
  end
  
  describe 'Input Validation and Sanitization' do
    it 'validates all required parameters' do
      # Test missing parameters
      post '/token', {}
      expect(last_response.status).to eq(400)
      
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_request')
      expect(response['error_description']).to include('grant_type')
    end
    
    it 'rejects oversized parameters' do
      # Very long parameters should be rejected
      oversized_code = 'a' * 10000
      
      post '/token', {
        grant_type: 'authorization_code',
        code: oversized_code,
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
      
      expect(last_response.status).to eq(400)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_request')
    end
    
    it 'sanitizes potentially dangerous input' do
      # SQL injection attempt in client_id
      malicious_client_id = "'; DROP TABLE clients; --"
      
      post '/token', {
        grant_type: 'authorization_code',
        code: 'valid_code',
        client_id: malicious_client_id,
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
      
      # Should handle gracefully without breaking
      expect(last_response.status).to be_between(400, 499)
      expect(last_response.body).not_to include('SQL')
      expect(last_response.body).not_to include('DROP TABLE')
    end
    
    it 'validates redirect_uri format' do
      invalid_uris = [
        'javascript:alert(1)',           # JavaScript URI
        'data:text/html,<script>alert(1)</script>',  # Data URI
        'file:///etc/passwd',            # File URI
        'not-a-uri',                     # Invalid format
        'http://[invalid-ipv6'           # Malformed IPv6
      ]
      
      invalid_uris.each do |uri|
        get "/authorize?client_id=test_client&response_type=code&redirect_uri=#{CGI.escape(uri)}"
        
        expect(last_response.status).to eq(400)
        expect(last_response.body).to include('invalid_redirect_uri')
      end
    end
  end
  
  describe 'Security Headers' do
    it 'includes appropriate security headers' do
      get '/authorize?client_id=test_client&response_type=code&redirect_uri=http://localhost:3000/callback'
      
      # Security headers should be present
      expect(last_response.headers['X-Frame-Options']).to eq('DENY')
      expect(last_response.headers['X-Content-Type-Options']).to eq('nosniff')
      expect(last_response.headers['X-XSS-Protection']).to eq('1; mode=block')
      expect(last_response.headers['Strict-Transport-Security']).to include('max-age=')
      expect(last_response.headers['Content-Security-Policy']).to be_present
    end
    
    it 'prevents clickjacking attacks' do
      get '/authorize?client_id=test_client&response_type=code&redirect_uri=http://localhost:3000/callback'
      
      expect(last_response.headers['X-Frame-Options']).to eq('DENY')
    end
    
    it 'includes CORS headers for API endpoints' do
      header 'Origin', 'https://trusted-client.example.com'
      get '/.well-known/openid_configuration'
      
      expect(last_response.headers['Access-Control-Allow-Origin']).to be_present
      expect(last_response.headers['Access-Control-Allow-Methods']).to include('GET')
    end
  end
  
  describe 'Timing Attack Prevention' do
    it 'uses constant-time string comparison for secrets' do
      start_time = Time.now
      
      # Invalid client secret
      post '/token', {
        grant_type: 'authorization_code',
        code: 'valid_code',
        client_id: 'test_client',
        client_secret: 'wrong_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
      
      invalid_time = Time.now - start_time
      
      start_time = Time.now
      
      # Valid client secret
      post '/token', {
        grant_type: 'authorization_code',
        code: 'valid_code',
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
      
      valid_time = Time.now - start_time
      
      # Timing difference should be minimal (< 10ms)
      time_difference = (invalid_time - valid_time).abs
      expect(time_difference).to be < 0.01
    end
  end
  
  describe 'Audit Logging' do
    let(:logger) { double('logger') }
    
    before do
      allow(Rails).to receive(:logger).and_return(logger)
    end
    
    it 'logs all authentication attempts' do
      expect(logger).to receive(:info).with(/OAuth2 token request/)
      
      post '/token', {
        grant_type: 'authorization_code',
        code: 'valid_code',
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
    end
    
    it 'logs security violations' do
      expect(logger).to receive(:warn).with(/Security violation: Invalid state parameter/)
      
      get '/callback?code=auth_code&state=invalid_state'
    end
    
    it 'includes client IP and user agent in logs' do
      expect(logger).to receive(:info).with(/IP: 127\.0\.0\.1.*User-Agent:/)
      
      header 'User-Agent', 'Test Client/1.0'
      post '/token', {
        grant_type: 'authorization_code',
        code: 'valid_code',
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
    end
  end
end