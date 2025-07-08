require 'spec_helper'
require 'oauth2/token_manager'

RSpec.describe OAuth2::TokenManager do
  let(:token_manager) { described_class.new }
  
  describe '#generate_access_token' do
    it 'generates access token with user and client information' do
      # Test 7: Access token - Token generation/validation
      user_id = 'user123'
      client_id = 'test_client'
      scope = 'read write'
      
      token_data = token_manager.generate_access_token(
        user_id: user_id,
        client_id: client_id,
        scope: scope
      )
      
      expect(token_data).to have_key(:access_token)
      expect(token_data).to have_key(:token_type)
      expect(token_data).to have_key(:expires_in)
      expect(token_data[:token_type]).to eq('Bearer')
      expect(token_data[:expires_in]).to be > 0
    end
    
    it 'generates different tokens for each call' do
      user_id = 'user123'
      client_id = 'test_client'
      
      token1 = token_manager.generate_access_token(user_id: user_id, client_id: client_id)
      token2 = token_manager.generate_access_token(user_id: user_id, client_id: client_id)
      
      expect(token1[:access_token]).not_to eq(token2[:access_token])
    end
  end
  
  describe '#validate_access_token' do
    it 'validates access token and returns token information' do
      user_id = 'user123'
      client_id = 'test_client'
      scope = 'read write'
      
      token_data = token_manager.generate_access_token(
        user_id: user_id,
        client_id: client_id,
        scope: scope
      )
      
      validated_data = token_manager.validate_access_token(token_data[:access_token])
      
      expect(validated_data).not_to be_nil
      expect(validated_data[:user_id]).to eq(user_id)
      expect(validated_data[:client_id]).to eq(client_id)
      expect(validated_data[:scope]).to eq(scope)
    end
    
    it 'returns nil for invalid access token' do
      validated_data = token_manager.validate_access_token('invalid_token')
      
      expect(validated_data).to be_nil
    end
    
    it 'returns nil for expired access token' do
      user_id = 'user123'
      client_id = 'test_client'
      
      token_data = token_manager.generate_access_token(
        user_id: user_id,
        client_id: client_id,
        expires_in: 1  # 1 second expiry for testing
      )
      
      sleep(2)  # Wait for token to expire
      
      validated_data = token_manager.validate_access_token(token_data[:access_token])
      
      expect(validated_data).to be_nil
    end
  end
  
  describe '#generate_refresh_token' do
    it 'generates refresh token for token refresh flow' do
      # Test 8: Refresh token - Token refresh flow
      user_id = 'user123'
      client_id = 'test_client'
      
      refresh_token = token_manager.generate_refresh_token(
        user_id: user_id,
        client_id: client_id
      )
      
      expect(refresh_token).to be_a(String)
      expect(refresh_token.length).to be > 10
    end
  end
  
  describe '#refresh_access_token' do
    it 'generates new access token using refresh token' do
      user_id = 'user123'
      client_id = 'test_client'
      
      refresh_token = token_manager.generate_refresh_token(
        user_id: user_id,
        client_id: client_id
      )
      
      new_token_data = token_manager.refresh_access_token(refresh_token)
      
      expect(new_token_data).to have_key(:access_token)
      expect(new_token_data).to have_key(:refresh_token)
      expect(new_token_data[:token_type]).to eq('Bearer')
    end
    
    it 'returns nil for invalid refresh token' do
      new_token_data = token_manager.refresh_access_token('invalid_refresh_token')
      
      expect(new_token_data).to be_nil
    end
    
    it 'invalidates old refresh token after use' do
      user_id = 'user123'
      client_id = 'test_client'
      
      refresh_token = token_manager.generate_refresh_token(
        user_id: user_id,
        client_id: client_id
      )
      
      # First use should succeed
      token_manager.refresh_access_token(refresh_token)
      
      # Second use of same refresh token should fail
      second_use_result = token_manager.refresh_access_token(refresh_token)
      
      expect(second_use_result).to be_nil
    end
  end
end