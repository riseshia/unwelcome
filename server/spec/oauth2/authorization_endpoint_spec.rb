require 'spec_helper'
require 'oauth2/authorization_endpoint'

RSpec.describe OAuth2::AuthorizationEndpoint do
  include Rack::Test::Methods
  
  def app
    OAuth2::AuthorizationEndpoint
  end
  
  describe 'GET /authorize' do
    it 'redirects to login when user is not authenticated' do
      # Test 5: Authorization endpoint - GET /authorize
      get '/authorize', {
        client_id: 'test_client',
        redirect_uri: 'http://localhost:3000/callback',
        response_type: 'code',
        scope: 'read'
      }
      
      expect(last_response.status).to eq(302)
      expect(last_response.headers['Location']).to include('/login')
    end
    
    it 'returns authorization page when user is authenticated' do
      # Mock user authentication
      header 'Authorization', 'Bearer mock_user_token'
      
      get '/authorize', {
        client_id: 'test_client',
        redirect_uri: 'http://localhost:3000/callback',
        response_type: 'code',
        scope: 'read'
      }
      
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('authorize')
      expect(last_response.body).to include('test_client')
    end
    
    it 'returns error for invalid client_id' do
      header 'Authorization', 'Bearer mock_user_token'
      
      get '/authorize', {
        client_id: 'invalid_client',
        redirect_uri: 'http://localhost:3000/callback',
        response_type: 'code',
        scope: 'read'
      }
      
      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('invalid_client')
    end
    
    it 'returns error for mismatched redirect_uri' do
      header 'Authorization', 'Bearer mock_user_token'
      
      get '/authorize', {
        client_id: 'test_client',
        redirect_uri: 'http://malicious.com/callback',
        response_type: 'code',
        scope: 'read'
      }
      
      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('invalid_redirect_uri')
    end
    
    it 'supports PKCE parameters' do
      header 'Authorization', 'Bearer mock_user_token'
      
      get '/authorize', {
        client_id: 'test_client',
        redirect_uri: 'http://localhost:3000/callback',
        response_type: 'code',
        scope: 'read',
        code_challenge: 'test_challenge',
        code_challenge_method: 'S256'
      }
      
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('authorize')
    end
  end
  
  describe 'POST /authorize' do
    it 'generates authorization code and redirects on user approval' do
      header 'Authorization', 'Bearer mock_user_token'
      
      post '/authorize', {
        client_id: 'test_client',
        redirect_uri: 'http://localhost:3000/callback',
        response_type: 'code',
        scope: 'read',
        user_action: 'approve'
      }
      
      expect(last_response.status).to eq(302)
      location = last_response.headers['Location']
      expect(location).to start_with('http://localhost:3000/callback?code=')
      expect(location).to include('state=') if last_request.params['state']
    end
    
    it 'redirects with error on user denial' do
      header 'Authorization', 'Bearer mock_user_token'
      
      post '/authorize', {
        client_id: 'test_client',
        redirect_uri: 'http://localhost:3000/callback',
        response_type: 'code',
        scope: 'read',
        user_action: 'deny'
      }
      
      expect(last_response.status).to eq(302)
      location = last_response.headers['Location']
      expect(location).to start_with('http://localhost:3000/callback?error=access_denied')
    end
  end
end