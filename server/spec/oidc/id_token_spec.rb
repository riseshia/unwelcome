require 'spec_helper'
require 'oidc/id_token'

RSpec.describe OIDC::IDToken do
  let(:id_token_generator) { described_class.new }
  
  describe '#generate' do
    it 'generates OIDC ID token with required claims' do
      # Test 9: ID token - OIDC ID token generation
      user_id = 'user123'
      client_id = 'test_client'
      user_info = {
        sub: user_id,
        email: 'user@example.com',
        name: 'Test User',
        preferred_username: 'testuser'
      }
      
      id_token = id_token_generator.generate(
        user_info: user_info,
        client_id: client_id,
        issuer: 'http://localhost:9292'
      )
      
      expect(id_token).to be_a(String)
      expect(id_token.split('.').length).to eq(3)  # JWT format
    end
    
    it 'includes required OIDC claims in ID token' do
      user_id = 'user123'
      client_id = 'test_client'
      user_info = {
        sub: user_id,
        email: 'user@example.com',
        name: 'Test User'
      }
      
      id_token = id_token_generator.generate(
        user_info: user_info,
        client_id: client_id,
        issuer: 'http://localhost:9292'
      )
      
      # Decode token to verify claims (without verification for test)
      payload = JWT.decode(id_token, nil, false)[0]
      
      expect(payload['sub']).to eq(user_id)
      expect(payload['aud']).to eq(client_id)
      expect(payload['iss']).to eq('http://localhost:9292')
      expect(payload['exp']).to be > Time.now.to_i
      expect(payload['iat']).to be <= Time.now.to_i
    end
    
    it 'includes custom claims when provided' do
      user_id = 'user123'
      client_id = 'test_client'
      user_info = {
        sub: user_id,
        email: 'user@example.com',
        name: 'Test User',
        custom_claim: 'custom_value'
      }
      
      id_token = id_token_generator.generate(
        user_info: user_info,
        client_id: client_id,
        issuer: 'http://localhost:9292'
      )
      
      payload = JWT.decode(id_token, nil, false)[0]
      
      expect(payload['custom_claim']).to eq('custom_value')
    end
    
    it 'sets appropriate expiration time' do
      user_id = 'user123'
      client_id = 'test_client'
      user_info = { sub: user_id }
      
      id_token = id_token_generator.generate(
        user_info: user_info,
        client_id: client_id,
        issuer: 'http://localhost:9292',
        expires_in: 1800  # 30 minutes
      )
      
      payload = JWT.decode(id_token, nil, false)[0]
      
      expect(payload['exp']).to be_within(60).of(Time.now.to_i + 1800)
    end
  end
  
  describe '#verify' do
    it 'verifies and decodes valid ID token' do
      user_id = 'user123'
      client_id = 'test_client'
      user_info = { sub: user_id }
      
      id_token = id_token_generator.generate(
        user_info: user_info,
        client_id: client_id,
        issuer: 'http://localhost:9292'
      )
      
      decoded_payload = id_token_generator.verify(id_token)
      
      expect(decoded_payload).not_to be_nil
      expect(decoded_payload['sub']).to eq(user_id)
      expect(decoded_payload['aud']).to eq(client_id)
    end
    
    it 'raises error for invalid ID token' do
      invalid_token = 'invalid.id.token'
      
      expect { id_token_generator.verify(invalid_token) }.to raise_error(JWT::DecodeError)
    end
    
    it 'raises error for expired ID token' do
      user_id = 'user123'
      client_id = 'test_client'
      user_info = { sub: user_id }
      
      id_token = id_token_generator.generate(
        user_info: user_info,
        client_id: client_id,
        issuer: 'http://localhost:9292',
        expires_in: 1  # 1 second expiry
      )
      
      sleep(2)  # Wait for token to expire
      
      expect { id_token_generator.verify(id_token) }.to raise_error(JWT::ExpiredSignature)
    end
  end
end