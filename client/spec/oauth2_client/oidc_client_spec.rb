require 'spec_helper'
require 'oauth2_client/oidc_client'

RSpec.describe OAuth2Client::OIDCClient do
  let(:client_id) { 'test_client_id' }
  let(:client_secret) { 'test_client_secret' }
  let(:issuer_url) { 'http://localhost:9292' }
  
  let(:oidc_client) do
    described_class.new(
      client_id: client_id,
      client_secret: client_secret,
      issuer_url: issuer_url
    )
  end
  
  describe '#verify_id_token' do
    it 'verifies and decodes valid ID token' do
      # Test 17: OIDC client - ID token validation
      # Mock JWT with valid structure (header.payload.signature)
      valid_id_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiYXVkIjoidGVzdF9jbGllbnRfaWQiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkyOTIiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTUxNjIzOTAyMn0.signature'
      
      # Mock JWT verification
      allow(JWT).to receive(:decode).with(
        valid_id_token,
        anything,
        true,
        hash_including(
          algorithm: 'HS256',
          aud: client_id,
          iss: issuer_url,
          verify_aud: true,
          verify_iss: true
        )
      ).and_return([
        {
          'sub' => 'user123',
          'aud' => client_id,
          'iss' => issuer_url,
          'exp' => 9999999999,
          'iat' => 1516239022
        },
        { 'alg' => 'HS256', 'typ' => 'JWT' }
      ])
      
      decoded_token = oidc_client.verify_id_token(valid_id_token)
      
      expect(decoded_token).not_to be_nil
      expect(decoded_token['sub']).to eq('user123')
      expect(decoded_token['aud']).to eq(client_id)
      expect(decoded_token['iss']).to eq(issuer_url)
    end
    
    it 'raises error for invalid ID token signature' do
      invalid_id_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.invalid_signature'
      
      allow(JWT).to receive(:decode).and_raise(JWT::VerificationError)
      
      expect {
        oidc_client.verify_id_token(invalid_id_token)
      }.to raise_error(OAuth2Client::OIDCClient::InvalidIDTokenError)
    end
    
    it 'raises error for expired ID token' do
      expired_id_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired.signature'
      
      allow(JWT).to receive(:decode).and_raise(JWT::ExpiredSignature)
      
      expect {
        oidc_client.verify_id_token(expired_id_token)
      }.to raise_error(OAuth2Client::OIDCClient::ExpiredIDTokenError)
    end
    
    it 'raises error for ID token with wrong audience' do
      wrong_audience_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.wrong_aud.signature'
      
      allow(JWT).to receive(:decode).and_raise(JWT::InvalidAudError)
      
      expect {
        oidc_client.verify_id_token(wrong_audience_token)
      }.to raise_error(OAuth2Client::OIDCClient::InvalidIDTokenError)
    end
    
    it 'raises error for ID token with wrong issuer' do
      wrong_issuer_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.wrong_iss.signature'
      
      allow(JWT).to receive(:decode).and_raise(JWT::InvalidIssuerError)
      
      expect {
        oidc_client.verify_id_token(wrong_issuer_token)
      }.to raise_error(OAuth2Client::OIDCClient::InvalidIDTokenError)
    end
  end
  
  describe '#get_public_key' do
    it 'fetches public key from JWKS endpoint' do
      kid = 'test_key_id'
      
      # Mock JWKS response
      stub_request(:get, "#{issuer_url}/.well-known/jwks.json")
        .to_return(
          status: 200,
          body: {
            keys: [
              {
                kty: 'RSA',
                use: 'sig',
                kid: kid,
                n: 'test_modulus',
                e: 'AQAB'
              }
            ]
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      public_key = oidc_client.get_public_key(kid)
      
      expect(public_key).not_to be_nil
    end
    
    it 'returns nil for non-existent key ID' do
      non_existent_kid = 'non_existent_key'
      
      stub_request(:get, "#{issuer_url}/.well-known/jwks.json")
        .to_return(
          status: 200,
          body: { keys: [] }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      public_key = oidc_client.get_public_key(non_existent_kid)
      
      expect(public_key).to be_nil
    end
  end
  
  describe '#discover_endpoints' do
    it 'discovers OIDC endpoints from discovery document' do
      # Mock discovery document response
      stub_request(:get, "#{issuer_url}/.well-known/openid_configuration")
        .to_return(
          status: 200,
          body: {
            issuer: issuer_url,
            authorization_endpoint: "#{issuer_url}/authorize",
            token_endpoint: "#{issuer_url}/token",
            userinfo_endpoint: "#{issuer_url}/userinfo",
            jwks_uri: "#{issuer_url}/.well-known/jwks.json"
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      endpoints = oidc_client.discover_endpoints
      
      expect(endpoints[:authorization_endpoint]).to eq("#{issuer_url}/authorize")
      expect(endpoints[:token_endpoint]).to eq("#{issuer_url}/token")
      expect(endpoints[:userinfo_endpoint]).to eq("#{issuer_url}/userinfo")
      expect(endpoints[:jwks_uri]).to eq("#{issuer_url}/.well-known/jwks.json")
    end
    
    it 'caches discovery document to avoid repeated requests' do
      stub_request(:get, "#{issuer_url}/.well-known/openid_configuration")
        .to_return(
          status: 200,
          body: {
            issuer: issuer_url,
            authorization_endpoint: "#{issuer_url}/authorize"
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      # First call
      endpoints1 = oidc_client.discover_endpoints
      # Second call should use cache
      endpoints2 = oidc_client.discover_endpoints
      
      expect(endpoints1).to eq(endpoints2)
      # Should only make one HTTP request
      expect(WebMock).to have_requested(:get, "#{issuer_url}/.well-known/openid_configuration").once
    end
  end
end