require 'spec_helper'
require 'oauth2_client/userinfo_request'

RSpec.describe OAuth2Client::UserInfoRequest do
  let(:access_token) { 'valid_access_token' }
  let(:userinfo_endpoint) { 'http://localhost:9292/userinfo' }
  
  let(:userinfo_request) do
    described_class.new(
      access_token: access_token,
      userinfo_endpoint: userinfo_endpoint
    )
  end
  
  describe '#fetch_user_info' do
    it 'fetches user information with valid access token' do
      # Test 18: UserInfo request - User info retrieval
      user_info_response = {
        sub: 'user123',
        name: 'Test User',
        email: 'user@example.com',
        preferred_username: 'testuser'
      }
      
      stub_request(:get, userinfo_endpoint)
        .with(
          headers: {
            'Authorization' => "Bearer #{access_token}",
            'Accept' => 'application/json'
          }
        )
        .to_return(
          status: 200,
          body: user_info_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      user_info = userinfo_request.fetch_user_info
      
      expect(user_info).to have_key(:sub)
      expect(user_info).to have_key(:name)
      expect(user_info).to have_key(:email)
      expect(user_info[:sub]).to eq('user123')
      expect(user_info[:name]).to eq('Test User')
      expect(user_info[:email]).to eq('user@example.com')
    end
    
    it 'supports POST method for user info request' do
      user_info_response = {
        sub: 'user123',
        name: 'Test User'
      }
      
      stub_request(:post, userinfo_endpoint)
        .with(
          body: { access_token: access_token },
          headers: {
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Accept' => 'application/json'
          }
        )
        .to_return(
          status: 200,
          body: user_info_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      user_info = userinfo_request.fetch_user_info(method: :post)
      
      expect(user_info[:sub]).to eq('user123')
      expect(user_info[:name]).to eq('Test User')
    end
    
    it 'raises error for invalid access token' do
      stub_request(:get, userinfo_endpoint)
        .to_return(
          status: 401,
          body: {
            error: 'invalid_token',
            error_description: 'The access token is invalid'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      expect {
        userinfo_request.fetch_user_info
      }.to raise_error(OAuth2Client::UserInfoRequest::InvalidTokenError)
    end
    
    it 'raises error for expired access token' do
      stub_request(:get, userinfo_endpoint)
        .to_return(
          status: 401,
          body: {
            error: 'invalid_token',
            error_description: 'The access token has expired'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      expect {
        userinfo_request.fetch_user_info
      }.to raise_error(OAuth2Client::UserInfoRequest::InvalidTokenError)
    end
    
    it 'raises error for insufficient scope' do
      stub_request(:get, userinfo_endpoint)
        .to_return(
          status: 403,
          body: {
            error: 'insufficient_scope',
            error_description: 'The access token does not have the required scope'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      expect {
        userinfo_request.fetch_user_info
      }.to raise_error(OAuth2Client::UserInfoRequest::InsufficientScopeError)
    end
    
    it 'handles network errors gracefully' do
      stub_request(:get, userinfo_endpoint).to_timeout
      
      expect {
        userinfo_request.fetch_user_info
      }.to raise_error(OAuth2Client::UserInfoRequest::NetworkError)
    end
    
    it 'includes custom headers when provided' do
      user_info_response = { sub: 'user123' }
      custom_headers = { 'X-Custom-Header' => 'custom_value' }
      
      stub_request(:get, userinfo_endpoint)
        .with(
          headers: {
            'Authorization' => "Bearer #{access_token}",
            'Accept' => 'application/json',
            'X-Custom-Header' => 'custom_value'
          }
        )
        .to_return(
          status: 200,
          body: user_info_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      
      user_info = userinfo_request.fetch_user_info(headers: custom_headers)
      
      expect(user_info[:sub]).to eq('user123')
    end
    
    it 'validates response content type' do
      stub_request(:get, userinfo_endpoint)
        .to_return(
          status: 200,
          body: 'not json',
          headers: { 'Content-Type' => 'text/plain' }
        )
      
      expect {
        userinfo_request.fetch_user_info
      }.to raise_error(OAuth2Client::UserInfoRequest::InvalidResponseError)
    end
    
    it 'handles rate limiting responses' do
      stub_request(:get, userinfo_endpoint)
        .to_return(
          status: 429,
          body: {
            error: 'rate_limit_exceeded',
            error_description: 'Too many requests'
          }.to_json,
          headers: { 
            'Content-Type' => 'application/json',
            'Retry-After' => '60'
          }
        )
      
      expect {
        userinfo_request.fetch_user_info
      }.to raise_error(OAuth2Client::UserInfoRequest::RateLimitError) do |error|
        expect(error.retry_after).to eq(60)
      end
    end
  end
end