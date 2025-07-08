require 'spec_helper'
require 'oauth2_client/authorization_code_flow'

RSpec.describe OAuth2Client::AuthorizationCodeFlow do
  let(:client_id) { 'test_client_id' }
  let(:client_secret) { 'test_client_secret' }
  let(:redirect_uri) { 'http://localhost:3000/callback' }
  let(:authorization_server_url) { 'http://localhost:9292' }
  
  let(:client) do
    described_class.new(
      client_id: client_id,
      client_secret: client_secret,
      redirect_uri: redirect_uri,
      authorization_server_url: authorization_server_url
    )
  end
  
  describe '#build_authorization_url' do
    it 'builds authorization URL with required parameters' do
      # Test 14: Authorization URL - Auth URL generation
      scope = 'read write'
      state = 'random_state_value'
      
      auth_url = client.build_authorization_url(
        scope: scope,
        state: state
      )
      
      expect(auth_url).to start_with("#{authorization_server_url}/authorize")
      expect(auth_url).to include("client_id=#{client_id}")
      expect(auth_url).to include("redirect_uri=#{CGI.escape(redirect_uri)}")
      expect(auth_url).to include("response_type=code")
      expect(auth_url).to include("scope=#{CGI.escape(scope)}")
      expect(auth_url).to include("state=#{state}")
    end
    
    it 'includes PKCE parameters when enabled' do
      scope = 'read write'
      state = 'random_state_value'
      
      auth_url = client.build_authorization_url(
        scope: scope,
        state: state,
        use_pkce: true
      )
      
      expect(auth_url).to include("code_challenge=")
      expect(auth_url).to include("code_challenge_method=S256")
    end
    
    it 'stores PKCE code_verifier for later use' do
      scope = 'read write'
      state = 'random_state_value'
      
      client.build_authorization_url(
        scope: scope,
        state: state,
        use_pkce: true
      )
      
      expect(client.instance_variable_get(:@code_verifier)).not_to be_nil
    end
    
    it 'includes additional parameters when provided' do
      scope = 'openid profile email'
      state = 'random_state_value'
      
      auth_url = client.build_authorization_url(
        scope: scope,
        state: state,
        additional_params: {
          prompt: 'consent',
          max_age: 3600
        }
      )
      
      expect(auth_url).to include("prompt=consent")
      expect(auth_url).to include("max_age=3600")
    end
    
    it 'properly URL encodes parameters' do
      scope = 'read write profile'
      state = 'state with spaces'
      
      auth_url = client.build_authorization_url(
        scope: scope,
        state: state
      )
      
      expect(auth_url).to include("scope=read%20write%20profile")
      expect(auth_url).to include("state=state%20with%20spaces")
    end
  end
  
  describe '#generate_state' do
    it 'generates random state parameter' do
      state1 = client.generate_state
      state2 = client.generate_state
      
      expect(state1).to be_a(String)
      expect(state1.length).to be > 10
      expect(state1).not_to eq(state2)
    end
    
    it 'generates URL-safe state parameter' do
      state = client.generate_state
      
      expect(state).to match(/\A[a-zA-Z0-9_-]+\z/)
    end
  end
  
  describe '#validate_state' do
    it 'validates state parameter against stored value' do
      original_state = 'test_state_value'
      client.instance_variable_set(:@state, original_state)
      
      expect(client.validate_state(original_state)).to be true
      expect(client.validate_state('different_state')).to be false
    end
    
    it 'returns false when no state is stored' do
      expect(client.validate_state('any_state')).to be false
    end
  end
end