require 'spec_helper'

RSpec.describe 'OAuth2/OIDC Error Handling', type: :feature do
  include Capybara::DSL
  
  describe 'Authorization Server Errors' do
    it 'handles invalid client_id gracefully' do
      # Test 24: Error handling - Error cases
      visit '/authorize?client_id=invalid_client&response_type=code&redirect_uri=http://localhost:3000/callback'
      
      expect(page.status_code).to eq(400)
      expect(page).to have_content('invalid_client')
      expect(page).to have_content('Client not found or invalid')
      expect(page).not_to have_content('Internal Server Error')
    end
    
    it 'handles mismatched redirect_uri securely' do
      visit '/authorize?client_id=test_client&response_type=code&redirect_uri=http://malicious.com/callback'
      
      expect(page.status_code).to eq(400)
      expect(page).to have_content('invalid_redirect_uri')
      expect(page).to have_content('Redirect URI not registered')
      
      # Should NOT redirect to the malicious URI
      expect(current_url).not_to include('malicious.com')
    end
    
    it 'handles unsupported response_type' do
      visit '/authorize?client_id=test_client&response_type=token&redirect_uri=http://localhost:3000/callback'
      
      expect(page.status_code).to eq(400)
      expect(page).to have_content('unsupported_response_type')
      expect(page).to have_content('Only authorization code flow is supported')
    end
    
    it 'handles invalid scope values' do
      visit '/authorize?client_id=test_client&response_type=code&scope=invalid_scope&redirect_uri=http://localhost:3000/callback'
      
      expect(page.status_code).to eq(400)
      expect(page).to have_content('invalid_scope')
      expect(page).to have_content('Requested scope is not supported')
    end
    
    it 'handles malformed PKCE parameters' do
      # Invalid code_challenge_method
      visit '/authorize?client_id=test_client&response_type=code&redirect_uri=http://localhost:3000/callback&code_challenge=test&code_challenge_method=MD5'
      
      expect(page.status_code).to eq(400)
      expect(page).to have_content('invalid_request')
      expect(page).to have_content('Unsupported code challenge method')
    end
  end
  
  describe 'Token Endpoint Errors' do
    include Rack::Test::Methods
    
    def app
      # Load token endpoint app
      require_relative '../../server/lib/oauth2/token_endpoint'
      OAuth2::TokenEndpoint
    end
    
    it 'handles invalid authorization code' do
      post '/token', {
        grant_type: 'authorization_code',
        code: 'invalid_code',
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
      
      expect(last_response.status).to eq(400)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_grant')
      expect(response['error_description']).to include('Invalid authorization code')
    end
    
    it 'handles expired authorization code' do
      post '/token', {
        grant_type: 'authorization_code',
        code: 'expired_code',
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
      
      expect(last_response.status).to eq(400)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_grant')
      expect(response['error_description']).to include('expired')
    end
    
    it 'handles invalid client credentials' do
      post '/token', {
        grant_type: 'authorization_code',
        code: 'valid_code',
        client_id: 'test_client',
        client_secret: 'wrong_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
      
      expect(last_response.status).to eq(401)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_client')
    end
    
    it 'handles PKCE verification failure' do
      post '/token', {
        grant_type: 'authorization_code',
        code: 'valid_code_with_pkce',
        client_id: 'test_client',
        redirect_uri: 'http://localhost:3000/callback',
        code_verifier: 'wrong_verifier'
      }
      
      expect(last_response.status).to eq(400)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_grant')
      expect(response['error_description']).to include('PKCE verification failed')
    end
    
    it 'handles missing required parameters' do
      post '/token', {
        grant_type: 'authorization_code'
        # Missing code, client_id, etc.
      }
      
      expect(last_response.status).to eq(400)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_request')
      expect(response['error_description']).to include('Missing required parameter')
    end
    
    it 'handles unsupported grant types' do
      post '/token', {
        grant_type: 'password',
        username: 'user',
        password: 'pass',
        client_id: 'test_client',
        client_secret: 'test_secret'
      }
      
      expect(last_response.status).to eq(400)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('unsupported_grant_type')
    end
    
    it 'handles malformed refresh token requests' do
      post '/token', {
        grant_type: 'refresh_token',
        refresh_token: 'invalid_refresh_token',
        client_id: 'test_client',
        client_secret: 'test_secret'
      }
      
      expect(last_response.status).to eq(400)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_grant')
    end
  end
  
  describe 'UserInfo Endpoint Errors' do
    include Rack::Test::Methods
    
    def app
      require_relative '../../server/lib/oidc/userinfo_endpoint'
      OIDC::UserInfoEndpoint
    end
    
    it 'handles missing access token' do
      get '/userinfo'
      
      expect(last_response.status).to eq(401)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_token')
      expect(response['error_description']).to include('Missing access token')
    end
    
    it 'handles invalid access token' do
      header 'Authorization', 'Bearer invalid_token'
      get '/userinfo'
      
      expect(last_response.status).to eq(401)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_token')
    end
    
    it 'handles expired access token' do
      header 'Authorization', 'Bearer expired_token'
      get '/userinfo'
      
      expect(last_response.status).to eq(401)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_token')
      expect(response['error_description']).to include('expired')
    end
    
    it 'handles insufficient scope for userinfo' do
      header 'Authorization', 'Bearer token_without_openid_scope'
      get '/userinfo'
      
      expect(last_response.status).to eq(403)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('insufficient_scope')
      expect(response['error_description']).to include('openid scope required')
    end
  end
  
  describe 'Client Library Error Handling' do
    let(:client) do
      OAuth2Client::AuthorizationCodeFlow.new(
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback',
        authorization_server_url: 'http://localhost:9292'
      )
    end
    
    it 'handles network timeouts gracefully' do
      stub_request(:post, "http://localhost:9292/token").to_timeout
      
      expect {
        client.exchange_code_for_token('test_code')
      }.to raise_error(OAuth2Client::NetworkError) do |error|
        expect(error.message).to include('Connection timeout')
        expect(error.retry_after).to be_nil
      end
    end
    
    it 'handles rate limiting responses' do
      stub_request(:post, "http://localhost:9292/token")
        .to_return(
          status: 429,
          headers: { 'Retry-After' => '60' },
          body: { error: 'rate_limit_exceeded' }.to_json
        )
      
      expect {
        client.exchange_code_for_token('test_code')
      }.to raise_error(OAuth2Client::RateLimitError) do |error|
        expect(error.retry_after).to eq(60)
      end
    end
    
    it 'handles malformed JSON responses' do
      stub_request(:post, "http://localhost:9292/token")
        .to_return(
          status: 200,
          body: 'invalid json{'
        )
      
      expect {
        client.exchange_code_for_token('test_code')
      }.to raise_error(OAuth2Client::InvalidResponseError)
    end
    
    it 'handles SSL certificate errors' do
      stub_request(:post, "https://localhost:9292/token")
        .to_raise(OpenSSL::SSL::SSLError.new('certificate verify failed'))
      
      ssl_client = OAuth2Client::AuthorizationCodeFlow.new(
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback',
        authorization_server_url: 'https://localhost:9292'
      )
      
      expect {
        ssl_client.exchange_code_for_token('test_code')
      }.to raise_error(OAuth2Client::SSLError)
    end
  end
  
  describe 'Security Error Scenarios' do
    it 'prevents authorization code replay attacks' do
      # Use the same authorization code twice
      auth_code = 'test_authorization_code'
      
      # First use should succeed
      post '/token', {
        grant_type: 'authorization_code',
        code: auth_code,
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
      expect(last_response.status).to eq(200)
      
      # Second use should fail
      post '/token', {
        grant_type: 'authorization_code',
        code: auth_code,
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
      expect(last_response.status).to eq(400)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_grant')
    end
    
    it 'prevents cross-client authorization code usage' do
      auth_code = 'client1_authorization_code'
      
      # Try to use client1's code with client2's credentials
      post '/token', {
        grant_type: 'authorization_code',
        code: auth_code,
        client_id: 'different_client',
        client_secret: 'different_secret',
        redirect_uri: 'http://localhost:3000/callback'
      }
      
      expect(last_response.status).to eq(400)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_grant')
    end
    
    it 'validates redirect_uri consistency' do
      # Code was issued for one redirect_uri, but token request uses different one
      auth_code = 'test_authorization_code'
      
      post '/token', {
        grant_type: 'authorization_code',
        code: auth_code,
        client_id: 'test_client',
        client_secret: 'test_secret',
        redirect_uri: 'http://different.com/callback'  # Different from original
      }
      
      expect(last_response.status).to eq(400)
      response = JSON.parse(last_response.body)
      expect(response['error']).to eq('invalid_grant')
      expect(response['error_description']).to include('redirect_uri mismatch')
    end
  end
  
  describe 'Logging and Monitoring' do
    it 'logs security-relevant events' do
      # Mock logger
      logger = double('logger')
      allow(Rails).to receive(:logger).and_return(logger)
      
      # Failed login attempt should be logged
      expect(logger).to receive(:warn).with(/Failed login attempt/)
      
      post '/token', {
        grant_type: 'authorization_code',
        code: 'invalid_code',
        client_id: 'test_client',
        client_secret: 'wrong_secret'
      }
    end
    
    it 'includes correlation IDs in error responses' do
      post '/token', {
        grant_type: 'authorization_code',
        code: 'invalid_code'
      }
      
      expect(last_response.status).to eq(400)
      response = JSON.parse(last_response.body)
      expect(response).to have_key('correlation_id')
      expect(response['correlation_id']).to match(/\A[a-f0-9-]+\z/)
    end
  end
end