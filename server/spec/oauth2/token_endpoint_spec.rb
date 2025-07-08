require 'spec_helper'
require 'oauth2/token_endpoint'

RSpec.describe OAuth2::TokenEndpoint do
  include Rack::Test::Methods
  
  def app
    OAuth2::TokenEndpoint
  end
  
  describe 'POST /token' do
    context 'authorization_code grant' do
      it 'exchanges authorization code for access token' do
        # Test 6: Token endpoint - POST /token
        post '/token', {
          grant_type: 'authorization_code',
          code: 'valid_auth_code',
          client_id: 'test_client',
          client_secret: 'test_secret',
          redirect_uri: 'http://localhost:3000/callback'
        }
        
        expect(last_response.status).to eq(200)
        expect(last_response.headers['Content-Type']).to include('application/json')
        
        response_data = JSON.parse(last_response.body)
        expect(response_data).to have_key('access_token')
        expect(response_data).to have_key('token_type')
        expect(response_data).to have_key('expires_in')
        expect(response_data['token_type']).to eq('Bearer')
      end
      
      it 'returns OIDC id_token when openid scope is requested' do
        post '/token', {
          grant_type: 'authorization_code',
          code: 'valid_auth_code_with_openid',
          client_id: 'test_client',
          client_secret: 'test_secret',
          redirect_uri: 'http://localhost:3000/callback'
        }
        
        expect(last_response.status).to eq(200)
        
        response_data = JSON.parse(last_response.body)
        expect(response_data).to have_key('id_token')
        expect(response_data['id_token']).to be_a(String)
      end
      
      it 'returns error for invalid authorization code' do
        post '/token', {
          grant_type: 'authorization_code',
          code: 'invalid_code',
          client_id: 'test_client',
          client_secret: 'test_secret',
          redirect_uri: 'http://localhost:3000/callback'
        }
        
        expect(last_response.status).to eq(400)
        
        response_data = JSON.parse(last_response.body)
        expect(response_data['error']).to eq('invalid_grant')
      end
      
      it 'validates PKCE code_verifier when code_challenge was used' do
        post '/token', {
          grant_type: 'authorization_code',
          code: 'valid_auth_code_with_pkce',
          client_id: 'test_client',
          redirect_uri: 'http://localhost:3000/callback',
          code_verifier: 'valid_code_verifier'
        }
        
        expect(last_response.status).to eq(200)
        
        response_data = JSON.parse(last_response.body)
        expect(response_data).to have_key('access_token')
      end
      
      it 'returns error for invalid PKCE code_verifier' do
        post '/token', {
          grant_type: 'authorization_code',
          code: 'valid_auth_code_with_pkce',
          client_id: 'test_client',
          redirect_uri: 'http://localhost:3000/callback',
          code_verifier: 'invalid_code_verifier'
        }
        
        expect(last_response.status).to eq(400)
        
        response_data = JSON.parse(last_response.body)
        expect(response_data['error']).to eq('invalid_grant')
      end
    end
    
    context 'refresh_token grant' do
      it 'exchanges refresh token for new access token' do
        post '/token', {
          grant_type: 'refresh_token',
          refresh_token: 'valid_refresh_token',
          client_id: 'test_client',
          client_secret: 'test_secret'
        }
        
        expect(last_response.status).to eq(200)
        
        response_data = JSON.parse(last_response.body)
        expect(response_data).to have_key('access_token')
        expect(response_data).to have_key('refresh_token')
        expect(response_data['token_type']).to eq('Bearer')
      end
      
      it 'returns error for invalid refresh token' do
        post '/token', {
          grant_type: 'refresh_token',
          refresh_token: 'invalid_refresh_token',
          client_id: 'test_client',
          client_secret: 'test_secret'
        }
        
        expect(last_response.status).to eq(400)
        
        response_data = JSON.parse(last_response.body)
        expect(response_data['error']).to eq('invalid_grant')
      end
    end
    
    it 'returns error for unsupported grant type' do
      post '/token', {
        grant_type: 'unsupported_grant',
        client_id: 'test_client',
        client_secret: 'test_secret'
      }
      
      expect(last_response.status).to eq(400)
      
      response_data = JSON.parse(last_response.body)
      expect(response_data['error']).to eq('unsupported_grant_type')
    end
  end
end