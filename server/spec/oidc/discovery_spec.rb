require 'spec_helper'
require 'oidc/discovery'

RSpec.describe OIDC::Discovery do
  include Rack::Test::Methods
  
  def app
    OIDC::Discovery
  end
  
  describe 'GET /.well-known/openid_configuration' do
    it 'returns OpenID Connect discovery document' do
      # Test 11: OIDC Discovery - /.well-known/openid_configuration
      get '/.well-known/openid_configuration'
      
      expect(last_response.status).to eq(200)
      expect(last_response.headers['Content-Type']).to include('application/json')
      
      discovery_doc = JSON.parse(last_response.body)
      expect(discovery_doc).to have_key('issuer')
      expect(discovery_doc).to have_key('authorization_endpoint')
      expect(discovery_doc).to have_key('token_endpoint')
      expect(discovery_doc).to have_key('userinfo_endpoint')
      expect(discovery_doc).to have_key('jwks_uri')
    end
    
    it 'includes required OIDC endpoints' do
      get '/.well-known/openid_configuration'
      
      discovery_doc = JSON.parse(last_response.body)
      
      expect(discovery_doc['issuer']).to eq('http://localhost:9292')
      expect(discovery_doc['authorization_endpoint']).to eq('http://localhost:9292/authorize')
      expect(discovery_doc['token_endpoint']).to eq('http://localhost:9292/token')
      expect(discovery_doc['userinfo_endpoint']).to eq('http://localhost:9292/userinfo')
      expect(discovery_doc['jwks_uri']).to eq('http://localhost:9292/.well-known/jwks.json')
    end
    
    it 'includes supported response types' do
      get '/.well-known/openid_configuration'
      
      discovery_doc = JSON.parse(last_response.body)
      
      expect(discovery_doc['response_types_supported']).to include('code')
      expect(discovery_doc['response_modes_supported']).to include('query')
    end
    
    it 'includes supported grant types' do
      get '/.well-known/openid_configuration'
      
      discovery_doc = JSON.parse(last_response.body)
      
      expect(discovery_doc['grant_types_supported']).to include('authorization_code')
      expect(discovery_doc['grant_types_supported']).to include('refresh_token')
    end
    
    it 'includes supported scopes' do
      get '/.well-known/openid_configuration'
      
      discovery_doc = JSON.parse(last_response.body)
      
      expect(discovery_doc['scopes_supported']).to include('openid')
      expect(discovery_doc['scopes_supported']).to include('profile')
      expect(discovery_doc['scopes_supported']).to include('email')
    end
    
    it 'includes supported claims' do
      get '/.well-known/openid_configuration'
      
      discovery_doc = JSON.parse(last_response.body)
      
      expect(discovery_doc['claims_supported']).to include('sub')
      expect(discovery_doc['claims_supported']).to include('name')
      expect(discovery_doc['claims_supported']).to include('email')
      expect(discovery_doc['claims_supported']).to include('preferred_username')
    end
    
    it 'includes token endpoint authentication methods' do
      get '/.well-known/openid_configuration'
      
      discovery_doc = JSON.parse(last_response.body)
      
      expect(discovery_doc['token_endpoint_auth_methods_supported']).to include('client_secret_post')
      expect(discovery_doc['token_endpoint_auth_methods_supported']).to include('client_secret_basic')
    end
    
    it 'includes PKCE support' do
      get '/.well-known/openid_configuration'
      
      discovery_doc = JSON.parse(last_response.body)
      
      expect(discovery_doc['code_challenge_methods_supported']).to include('S256')
      expect(discovery_doc['code_challenge_methods_supported']).to include('plain')
    end
  end
  
  describe 'GET /.well-known/jwks.json' do
    it 'returns JSON Web Key Set' do
      get '/.well-known/jwks.json'
      
      expect(last_response.status).to eq(200)
      expect(last_response.headers['Content-Type']).to include('application/json')
      
      jwks = JSON.parse(last_response.body)
      expect(jwks).to have_key('keys')
      expect(jwks['keys']).to be_a(Array)
      expect(jwks['keys'].length).to be > 0
    end
    
    it 'includes required JWK properties' do
      get '/.well-known/jwks.json'
      
      jwks = JSON.parse(last_response.body)
      key = jwks['keys'].first
      
      expect(key).to have_key('kty')  # Key type
      expect(key).to have_key('use')  # Key use
      expect(key).to have_key('kid')  # Key ID
      expect(key).to have_key('alg')  # Algorithm
    end
  end
end