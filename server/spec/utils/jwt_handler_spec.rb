require 'spec_helper'
require 'utils/jwt_handler'

RSpec.describe Utils::JWTHandler do
  let(:secret_key) { 'test-secret-key' }
  let(:jwt_handler) { described_class.new(secret_key) }
  
  describe '#generate_token' do
    it 'generates a JWT token with given payload' do
      payload = { user_id: 123, exp: Time.now.to_i + 3600 }
      
      token = jwt_handler.generate_token(payload)
      
      expect(token).to be_a(String)
      expect(token.split('.').length).to eq(3)
    end
  end
  
  describe '#verify_token' do
    it 'verifies and decodes a valid JWT token' do
      payload = { user_id: 123, exp: Time.now.to_i + 3600 }
      token = jwt_handler.generate_token(payload)
      
      decoded_payload = jwt_handler.verify_token(token)
      
      expect(decoded_payload['user_id']).to eq(123)
    end
    
    it 'raises error for invalid token' do
      invalid_token = 'invalid.token.here'
      
      expect { jwt_handler.verify_token(invalid_token) }.to raise_error(JWT::DecodeError)
    end
    
    it 'raises error for expired token' do
      expired_payload = { user_id: 123, exp: Time.now.to_i - 3600 }
      expired_token = jwt_handler.generate_token(expired_payload)
      
      expect { jwt_handler.verify_token(expired_token) }.to raise_error(JWT::ExpiredSignature)
    end
  end
end