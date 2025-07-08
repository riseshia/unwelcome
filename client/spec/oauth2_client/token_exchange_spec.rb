require 'spec_helper'
require 'oauth2_client/token_exchange'

RSpec.describe OAuth2Client::TokenExchange do
  let(:client_id) { 'test_client_id' }
  let(:client_secret) { 'test_client_secret' }
  let(:redirect_uri) { 'http://localhost:3000/callback' }
  let(:authorization_server_url) { 'http://localhost:9292' }
  
  let(:token_exchange) do
    described_class.new(
      client_id: client_id,
      client_secret: client_secret,
      redirect_uri: redirect_uri,
      authorization_server_url: authorization_server_url
    )
  end
  
  describe '#exchange_code_for_token' do
    it 'exchanges authorization code for access token' do
      # Test 15: Token exchange - Authorization code to token
      authorization_code = 'valid_authorization_code'
      
      # Mock successful token response
      stub_request(:post, "#{authorization_server_url}/token")
        .with(
          body: {
            grant_type: 'authorization_code',
            code: authorization_code,
            client_id: client_id,
            client_secret: client_secret,
            redirect_uri: redirect_uri
          },
          headers: {
            'Content-Type' => 'application/x-www-form-urlencoded'
          }
        )
        .to_return(
          status: 200,
          body: {
            access_token: 'access_token_value',
            token_type: 'Bearer',
            expires_in: 3600,
            refresh_token: 'refresh_token_value'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      token_response = token_exchange.exchange_code_for_token(authorization_code)
      
      expect(token_response).to have_key(:access_token)
      expect(token_response).to have_key(:token_type)
      expect(token_response).to have_key(:expires_in)
      expect(token_response).to have_key(:refresh_token)
      expect(token_response[:access_token]).to eq('access_token_value')
      expect(token_response[:token_type]).to eq('Bearer')
    end
    
    it 'includes PKCE code_verifier when provided' do
      authorization_code = 'valid_authorization_code'
      code_verifier = 'test_code_verifier'
      
      stub_request(:post, "#{authorization_server_url}/token")
        .with(
          body: {
            grant_type: 'authorization_code',
            code: authorization_code,
            client_id: client_id,
            client_secret: client_secret,
            redirect_uri: redirect_uri,
            code_verifier: code_verifier
          }
        )
        .to_return(
          status: 200,
          body: {
            access_token: 'access_token_value',
            token_type: 'Bearer',
            expires_in: 3600
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      token_response = token_exchange.exchange_code_for_token(
        authorization_code,
        code_verifier: code_verifier
      )
      
      expect(token_response[:access_token]).to eq('access_token_value')
    end
    
    it 'returns OIDC id_token when present in response' do
      authorization_code = 'valid_authorization_code'
      
      stub_request(:post, "#{authorization_server_url}/token")
        .to_return(
          status: 200,
          body: {
            access_token: 'access_token_value',
            token_type: 'Bearer',
            expires_in: 3600,
            id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      token_response = token_exchange.exchange_code_for_token(authorization_code)
      
      expect(token_response).to have_key(:id_token)
      expect(token_response[:id_token]).to start_with('eyJ')
    end
    
    it 'raises error for invalid authorization code' do
      authorization_code = 'invalid_authorization_code'
      
      stub_request(:post, "#{authorization_server_url}/token")
        .to_return(
          status: 400,
          body: {
            error: 'invalid_grant',
            error_description: 'Invalid authorization code'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      expect {
        token_exchange.exchange_code_for_token(authorization_code)
      }.to raise_error(OAuth2Client::TokenExchange::InvalidGrantError)
    end
    
    it 'raises error for invalid client credentials' do
      authorization_code = 'valid_authorization_code'
      
      stub_request(:post, "#{authorization_server_url}/token")
        .to_return(
          status: 401,
          body: {
            error: 'invalid_client',
            error_description: 'Invalid client credentials'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      expect {
        token_exchange.exchange_code_for_token(authorization_code)
      }.to raise_error(OAuth2Client::TokenExchange::InvalidClientError)
    end
  end
  
  describe '#refresh_token' do
    it 'exchanges refresh token for new access token' do
      refresh_token = 'valid_refresh_token'
      
      stub_request(:post, "#{authorization_server_url}/token")
        .with(
          body: {
            grant_type: 'refresh_token',
            refresh_token: refresh_token,
            client_id: client_id,
            client_secret: client_secret
          }
        )
        .to_return(
          status: 200,
          body: {
            access_token: 'new_access_token_value',
            token_type: 'Bearer',
            expires_in: 3600,
            refresh_token: 'new_refresh_token_value'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      token_response = token_exchange.refresh_token(refresh_token)
      
      expect(token_response[:access_token]).to eq('new_access_token_value')
      expect(token_response[:refresh_token]).to eq('new_refresh_token_value')
    end
    
    it 'raises error for invalid refresh token' do
      refresh_token = 'invalid_refresh_token'
      
      stub_request(:post, "#{authorization_server_url}/token")
        .to_return(
          status: 400,
          body: {
            error: 'invalid_grant',
            error_description: 'Invalid refresh token'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      expect {
        token_exchange.refresh_token(refresh_token)
      }.to raise_error(OAuth2Client::TokenExchange::InvalidGrantError)
    end
  end
end