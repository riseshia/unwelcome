require 'spec_helper'
require 'oidc/userinfo_endpoint'

RSpec.describe OIDC::UserInfoEndpoint do
  include Rack::Test::Methods
  
  def app
    OIDC::UserInfoEndpoint
  end
  
  describe 'GET /userinfo' do
    it 'returns user information with valid access token' do
      # Test 10: UserInfo endpoint - GET /userinfo
      header 'Authorization', 'Bearer valid_access_token'
      
      get '/userinfo'
      
      expect(last_response.status).to eq(200)
      expect(last_response.headers['Content-Type']).to include('application/json')
      
      user_info = JSON.parse(last_response.body)
      expect(user_info).to have_key('sub')
      expect(user_info['sub']).to be_a(String)
    end
    
    it 'returns standard OIDC claims' do
      header 'Authorization', 'Bearer valid_access_token_with_profile'
      
      get '/userinfo'
      
      expect(last_response.status).to eq(200)
      
      user_info = JSON.parse(last_response.body)
      expect(user_info).to have_key('sub')
      expect(user_info).to have_key('email')
      expect(user_info).to have_key('name')
      expect(user_info).to have_key('preferred_username')
    end
    
    it 'returns only claims authorized by scope' do
      # Token with only 'openid' scope, no 'profile' or 'email'
      header 'Authorization', 'Bearer valid_access_token_openid_only'
      
      get '/userinfo'
      
      expect(last_response.status).to eq(200)
      
      user_info = JSON.parse(last_response.body)
      expect(user_info).to have_key('sub')
      expect(user_info).not_to have_key('email')
      expect(user_info).not_to have_key('name')
    end
    
    it 'returns error for missing access token' do
      get '/userinfo'
      
      expect(last_response.status).to eq(401)
      
      error_response = JSON.parse(last_response.body)
      expect(error_response['error']).to eq('invalid_token')
    end
    
    it 'returns error for invalid access token' do
      header 'Authorization', 'Bearer invalid_access_token'
      
      get '/userinfo'
      
      expect(last_response.status).to eq(401)
      
      error_response = JSON.parse(last_response.body)
      expect(error_response['error']).to eq('invalid_token')
    end
    
    it 'returns error for expired access token' do
      header 'Authorization', 'Bearer expired_access_token'
      
      get '/userinfo'
      
      expect(last_response.status).to eq(401)
      
      error_response = JSON.parse(last_response.body)
      expect(error_response['error']).to eq('invalid_token')
    end
    
    it 'returns error for access token without openid scope' do
      header 'Authorization', 'Bearer valid_access_token_no_openid'
      
      get '/userinfo'
      
      expect(last_response.status).to eq(403)
      
      error_response = JSON.parse(last_response.body)
      expect(error_response['error']).to eq('insufficient_scope')
    end
  end
  
  describe 'POST /userinfo' do
    it 'supports POST method with access token in body' do
      post '/userinfo', { access_token: 'valid_access_token' }
      
      expect(last_response.status).to eq(200)
      
      user_info = JSON.parse(last_response.body)
      expect(user_info).to have_key('sub')
    end
    
    it 'prioritizes Authorization header over body parameter' do
      header 'Authorization', 'Bearer valid_access_token_user1'
      
      post '/userinfo', { access_token: 'valid_access_token_user2' }
      
      expect(last_response.status).to eq(200)
      
      user_info = JSON.parse(last_response.body)
      # Should return user1 info, not user2
      expect(user_info['sub']).to eq('user1')
    end
  end
end