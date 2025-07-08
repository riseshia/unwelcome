require 'spec_helper'
require 'oauth2/client_registry'

RSpec.describe OAuth2::ClientRegistry do
  let(:client_registry) { described_class.new }
  
  describe '#register_client' do
    it 'registers a new OAuth2 client' do
      # Test 3: Client registry - Client registration/lookup
      client_id = 'test_client_id'
      client_secret = 'test_client_secret'
      redirect_uris = ['http://localhost:3000/callback']
      
      client_registry.register_client(
        client_id: client_id,
        client_secret: client_secret,
        redirect_uris: redirect_uris
      )
      
      client = client_registry.find_client(client_id)
      expect(client).not_to be_nil
      expect(client[:client_id]).to eq(client_id)
      expect(client[:redirect_uris]).to eq(redirect_uris)
    end
    
    it 'raises error when registering duplicate client_id' do
      client_id = 'duplicate_client'
      
      client_registry.register_client(
        client_id: client_id,
        client_secret: 'secret1',
        redirect_uris: ['http://localhost:3000/callback']
      )
      
      expect {
        client_registry.register_client(
          client_id: client_id,
          client_secret: 'secret2',
          redirect_uris: ['http://localhost:3001/callback']
        )
      }.to raise_error(OAuth2::ClientRegistry::DuplicateClientError)
    end
  end
  
  describe '#find_client' do
    it 'returns nil for non-existent client' do
      client = client_registry.find_client('non_existent_client')
      
      expect(client).to be_nil
    end
  end
  
  describe '#validate_client' do
    it 'validates client credentials' do
      client_id = 'test_client'
      client_secret = 'test_secret'
      
      client_registry.register_client(
        client_id: client_id,
        client_secret: client_secret,
        redirect_uris: ['http://localhost:3000/callback']
      )
      
      expect(client_registry.validate_client(client_id, client_secret)).to be true
      expect(client_registry.validate_client(client_id, 'wrong_secret')).to be false
    end
  end
end