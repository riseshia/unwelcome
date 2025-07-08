require 'spec_helper'
require 'oauth2_client/token_manager'

RSpec.describe OAuth2Client::TokenManager do
  let(:token_manager) { described_class.new }
  
  describe '#store_token' do
    it 'stores token data with expiration tracking' do
      # Test 16: Token management - Token storage/refresh
      token_data = {
        access_token: 'access_token_value',
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: 'refresh_token_value'
      }
      
      token_manager.store_token(token_data)
      
      stored_token = token_manager.get_token
      expect(stored_token[:access_token]).to eq('access_token_value')
      expect(stored_token[:token_type]).to eq('Bearer')
      expect(stored_token[:refresh_token]).to eq('refresh_token_value')
      expect(stored_token[:expires_at]).to be_a(Time)
    end
    
    it 'calculates expiration time from expires_in' do
      token_data = {
        access_token: 'access_token_value',
        expires_in: 3600
      }
      
      before_time = Time.now
      token_manager.store_token(token_data)
      after_time = Time.now
      
      stored_token = token_manager.get_token
      expect(stored_token[:expires_at]).to be_between(
        before_time + 3600,
        after_time + 3600
      )
    end
    
    it 'stores id_token when present' do
      token_data = {
        access_token: 'access_token_value',
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
      }
      
      token_manager.store_token(token_data)
      
      stored_token = token_manager.get_token
      expect(stored_token[:id_token]).to eq('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature')
    end
  end
  
  describe '#get_token' do
    it 'returns stored token data' do
      token_data = {
        access_token: 'access_token_value',
        token_type: 'Bearer',
        expires_in: 3600
      }
      
      token_manager.store_token(token_data)
      
      stored_token = token_manager.get_token
      expect(stored_token[:access_token]).to eq('access_token_value')
    end
    
    it 'returns nil when no token is stored' do
      stored_token = token_manager.get_token
      
      expect(stored_token).to be_nil
    end
  end
  
  describe '#get_access_token' do
    it 'returns access token string' do
      token_data = {
        access_token: 'access_token_value',
        token_type: 'Bearer',
        expires_in: 3600
      }
      
      token_manager.store_token(token_data)
      
      access_token = token_manager.get_access_token
      expect(access_token).to eq('access_token_value')
    end
    
    it 'returns nil when no token is stored' do
      access_token = token_manager.get_access_token
      
      expect(access_token).to be_nil
    end
  end
  
  describe '#token_expired?' do
    it 'returns false for valid token' do
      token_data = {
        access_token: 'access_token_value',
        expires_in: 3600
      }
      
      token_manager.store_token(token_data)
      
      expect(token_manager.token_expired?).to be false
    end
    
    it 'returns true for expired token' do
      token_data = {
        access_token: 'access_token_value',
        expires_in: 1
      }
      
      token_manager.store_token(token_data)
      sleep(2)
      
      expect(token_manager.token_expired?).to be true
    end
    
    it 'returns true when no token is stored' do
      expect(token_manager.token_expired?).to be true
    end
    
    it 'returns true when token expires within buffer time' do
      token_data = {
        access_token: 'access_token_value',
        expires_in: 30  # 30 seconds
      }
      
      token_manager.store_token(token_data)
      
      # Should return true if token expires within 60 seconds (default buffer)
      expect(token_manager.token_expired?).to be true
    end
    
    it 'respects custom buffer time' do
      token_data = {
        access_token: 'access_token_value',
        expires_in: 30  # 30 seconds
      }
      
      token_manager.store_token(token_data)
      
      # With 10 second buffer, should return false
      expect(token_manager.token_expired?(buffer_seconds: 10)).to be false
    end
  end
  
  describe '#clear_token' do
    it 'clears stored token data' do
      token_data = {
        access_token: 'access_token_value',
        token_type: 'Bearer',
        expires_in: 3600
      }
      
      token_manager.store_token(token_data)
      token_manager.clear_token
      
      expect(token_manager.get_token).to be_nil
    end
  end
  
  describe '#has_refresh_token?' do
    it 'returns true when refresh token is stored' do
      token_data = {
        access_token: 'access_token_value',
        refresh_token: 'refresh_token_value'
      }
      
      token_manager.store_token(token_data)
      
      expect(token_manager.has_refresh_token?).to be true
    end
    
    it 'returns false when no refresh token is stored' do
      token_data = {
        access_token: 'access_token_value'
      }
      
      token_manager.store_token(token_data)
      
      expect(token_manager.has_refresh_token?).to be false
    end
  end
  
  describe '#get_refresh_token' do
    it 'returns refresh token string' do
      token_data = {
        access_token: 'access_token_value',
        refresh_token: 'refresh_token_value'
      }
      
      token_manager.store_token(token_data)
      
      refresh_token = token_manager.get_refresh_token
      expect(refresh_token).to eq('refresh_token_value')
    end
    
    it 'returns nil when no refresh token is stored' do
      refresh_token = token_manager.get_refresh_token
      
      expect(refresh_token).to be_nil
    end
  end
end