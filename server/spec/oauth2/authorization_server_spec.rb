require 'spec_helper'
require 'oauth2/authorization_server'

RSpec.describe OAuth2::AuthorizationServer do
  let(:authorization_server) { described_class.new }
  
  describe '#generate_authorization_code' do
    it 'generates authorization code for valid client and redirect_uri' do
      # Test 4: Authorization code - Code generation/validation
      client_id = 'test_client'
      redirect_uri = 'http://localhost:3000/callback'
      user_id = 'user123'
      scope = 'read write'
      
      auth_code = authorization_server.generate_authorization_code(
        client_id: client_id,
        redirect_uri: redirect_uri,
        user_id: user_id,
        scope: scope
      )
      
      expect(auth_code).to be_a(String)
      expect(auth_code.length).to be > 10
    end
    
    it 'generates different codes for each request' do
      client_id = 'test_client'
      redirect_uri = 'http://localhost:3000/callback'
      user_id = 'user123'
      
      code1 = authorization_server.generate_authorization_code(
        client_id: client_id,
        redirect_uri: redirect_uri,
        user_id: user_id
      )
      
      code2 = authorization_server.generate_authorization_code(
        client_id: client_id,
        redirect_uri: redirect_uri,
        user_id: user_id
      )
      
      expect(code1).not_to eq(code2)
    end
  end
  
  describe '#validate_authorization_code' do
    it 'validates authorization code and returns code data' do
      client_id = 'test_client'
      redirect_uri = 'http://localhost:3000/callback'
      user_id = 'user123'
      
      auth_code = authorization_server.generate_authorization_code(
        client_id: client_id,
        redirect_uri: redirect_uri,
        user_id: user_id
      )
      
      code_data = authorization_server.validate_authorization_code(
        code: auth_code,
        client_id: client_id,
        redirect_uri: redirect_uri
      )
      
      expect(code_data).not_to be_nil
      expect(code_data[:user_id]).to eq(user_id)
      expect(code_data[:client_id]).to eq(client_id)
    end
    
    it 'returns nil for invalid authorization code' do
      code_data = authorization_server.validate_authorization_code(
        code: 'invalid_code',
        client_id: 'test_client',
        redirect_uri: 'http://localhost:3000/callback'
      )
      
      expect(code_data).to be_nil
    end
    
    it 'returns nil for expired authorization code' do
      # Test authorization code expiration (codes should expire after 10 minutes)
      client_id = 'test_client'
      redirect_uri = 'http://localhost:3000/callback'
      user_id = 'user123'
      
      auth_code = authorization_server.generate_authorization_code(
        client_id: client_id,
        redirect_uri: redirect_uri,
        user_id: user_id
      )
      
      # Simulate time passing (mock time or test with short expiry)
      allow(Time).to receive(:now).and_return(Time.now + 11.minutes)
      
      code_data = authorization_server.validate_authorization_code(
        code: auth_code,
        client_id: client_id,
        redirect_uri: redirect_uri
      )
      
      expect(code_data).to be_nil
    end
  end
end