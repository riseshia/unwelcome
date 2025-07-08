require 'spec_helper'
require_relative '../app'

RSpec.describe 'OAuth2 Callback', type: :feature do
  include Capybara::DSL
  
  before do
    Capybara.app = Sinatra::Application
  end
  
  describe 'GET /callback' do
    context 'successful authorization' do
      it 'exchanges authorization code for tokens and stores user info' do
        # Test 20: Callback handling - Authorization code processing
        authorization_code = 'valid_authorization_code'
        state = 'valid_state_parameter'
        code_verifier = 'test_code_verifier_1234567890abcdef'
        
        # Set session with stored state and code_verifier
        page.set_rack_session(
          oauth_state: state,
          code_verifier: code_verifier
        )
        
        # Mock token exchange response
        stub_request(:post, "http://localhost:9292/token")
          .with(
            body: {
              grant_type: 'authorization_code',
              code: authorization_code,
              client_id: 'sample_rp_client',
              client_secret: 'sample_rp_secret',
              redirect_uri: 'http://localhost:4567/callback',
              code_verifier: code_verifier
            }
          )
          .to_return(
            status: 200,
            body: {
              access_token: 'access_token_123',
              token_type: 'Bearer',
              expires_in: 3600,
              id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IlRlc3QgVXNlciIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSJ9.signature'
            }.to_json,
            headers: { 'Content-Type' => 'application/json' }
          )
        
        # Mock user info request
        stub_request(:get, "http://localhost:9292/userinfo")
          .with(
            headers: {
              'Authorization' => 'Bearer access_token_123'
            }
          )
          .to_return(
            status: 200,
            body: {
              sub: 'user123',
              name: 'Test User',
              email: 'user@example.com',
              preferred_username: 'testuser'
            }.to_json,
            headers: { 'Content-Type' => 'application/json' }
          )
        
        visit "/callback?code=#{authorization_code}&state=#{state}"
        
        expect(current_path).to eq('/')
        expect(page).to have_content('Welcome, Test User!')
        expect(page).to have_content('user@example.com')
        expect(page).to have_link('Logout')
      end
      
      it 'validates state parameter to prevent CSRF attacks' do
        authorization_code = 'valid_authorization_code'
        stored_state = 'stored_state_value'
        received_state = 'different_state_value'
        
        page.set_rack_session(oauth_state: stored_state)
        
        visit "/callback?code=#{authorization_code}&state=#{received_state}"
        
        expect(page).to have_content('Invalid state parameter')
        expect(page).to have_content('Possible CSRF attack')
        expect(current_path).to eq('/callback')
      end
      
      it 'clears session state after successful callback' do
        authorization_code = 'valid_authorization_code'
        state = 'valid_state_parameter'
        code_verifier = 'test_code_verifier_1234567890abcdef'
        
        page.set_rack_session(
          oauth_state: state,
          code_verifier: code_verifier
        )
        
        # Mock successful token exchange and user info
        stub_request(:post, "http://localhost:9292/token").to_return(
          status: 200,
          body: { access_token: 'token', token_type: 'Bearer' }.to_json
        )
        
        stub_request(:get, "http://localhost:9292/userinfo").to_return(
          status: 200,
          body: { sub: 'user123', name: 'Test User' }.to_json
        )
        
        visit "/callback?code=#{authorization_code}&state=#{state}"
        
        session = page.rack_session
        expect(session[:oauth_state]).to be_nil
        expect(session[:code_verifier]).to be_nil
        expect(session[:user_info]).not_to be_nil
      end
    end
    
    context 'authorization errors' do
      it 'handles authorization denied error' do
        visit '/callback?error=access_denied&error_description=User%20denied%20access'
        
        expect(page).to have_content('Authorization failed')
        expect(page).to have_content('access_denied')
        expect(page).to have_content('User denied access')
        expect(page).to have_link('Try Again', href: '/login')
      end
      
      it 'handles invalid_client error' do
        visit '/callback?error=invalid_client&error_description=Invalid%20client%20credentials'
        
        expect(page).to have_content('Authorization failed')
        expect(page).to have_content('invalid_client')
        expect(page).to have_content('Invalid client credentials')
      end
      
      it 'handles missing authorization code' do
        state = 'valid_state'
        page.set_rack_session(oauth_state: state)
        
        visit "/callback?state=#{state}"
        
        expect(page).to have_content('Authorization failed')
        expect(page).to have_content('Missing authorization code')
      end
    end
    
    context 'token exchange errors' do
      it 'handles invalid authorization code' do
        authorization_code = 'invalid_authorization_code'
        state = 'valid_state_parameter'
        
        page.set_rack_session(oauth_state: state)
        
        stub_request(:post, "http://localhost:9292/token")
          .to_return(
            status: 400,
            body: {
              error: 'invalid_grant',
              error_description: 'Invalid authorization code'
            }.to_json,
            headers: { 'Content-Type' => 'application/json' }
          )
        
        visit "/callback?code=#{authorization_code}&state=#{state}"
        
        expect(page).to have_content('Token exchange failed')
        expect(page).to have_content('invalid_grant')
        expect(page).to have_content('Invalid authorization code')
      end
      
      it 'handles network errors during token exchange' do
        authorization_code = 'valid_authorization_code'
        state = 'valid_state_parameter'
        
        page.set_rack_session(oauth_state: state)
        
        stub_request(:post, "http://localhost:9292/token").to_timeout
        
        visit "/callback?code=#{authorization_code}&state=#{state}"
        
        expect(page).to have_content('Network error')
        expect(page).to have_content('Unable to connect to authorization server')
      end
    end
    
    context 'user info retrieval errors' do
      it 'handles invalid access token for user info' do
        authorization_code = 'valid_authorization_code'
        state = 'valid_state_parameter'
        
        page.set_rack_session(oauth_state: state)
        
        stub_request(:post, "http://localhost:9292/token")
          .to_return(
            status: 200,
            body: { access_token: 'invalid_token', token_type: 'Bearer' }.to_json
          )
        
        stub_request(:get, "http://localhost:9292/userinfo")
          .to_return(
            status: 401,
            body: { error: 'invalid_token' }.to_json,
            headers: { 'Content-Type' => 'application/json' }
          )
        
        visit "/callback?code=#{authorization_code}&state=#{state}"
        
        expect(page).to have_content('User info retrieval failed')
        expect(page).to have_content('invalid_token')
      end
    end
  end
end