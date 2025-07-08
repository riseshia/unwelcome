require 'spec_helper'
require 'utils/crypto_utils'

RSpec.describe Utils::CryptoUtils do
  describe '.generate_secure_random' do
    it 'generates a secure random string of specified length' do
      # Test 2: Crypto utilities - Secure random string generation
      length = 32
      
      random_string = Utils::CryptoUtils.generate_secure_random(length)
      
      expect(random_string).to be_a(String)
      expect(random_string.length).to eq(length)
      expect(random_string).to match(/\A[a-zA-Z0-9_-]+\z/)
    end
    
    it 'generates different strings on each call' do
      string1 = Utils::CryptoUtils.generate_secure_random(16)
      string2 = Utils::CryptoUtils.generate_secure_random(16)
      
      expect(string1).not_to eq(string2)
    end
  end
  
  describe '.base64_url_encode' do
    it 'encodes string to base64 URL safe format' do
      input = 'hello world'
      
      encoded = Utils::CryptoUtils.base64_url_encode(input)
      
      expect(encoded).to be_a(String)
      expect(encoded).not_to include('=')  # URL safe means no padding
      expect(encoded).not_to include('+')
      expect(encoded).not_to include('/')
    end
  end
  
  describe '.sha256_hash' do
    it 'creates SHA256 hash of input string' do
      input = 'test_string'
      
      hash = Utils::CryptoUtils.sha256_hash(input)
      
      expect(hash).to be_a(String)
      expect(hash.length).to eq(64)  # SHA256 hex string length
      expect(hash).to match(/\A[a-f0-9]+\z/)
    end
  end
end