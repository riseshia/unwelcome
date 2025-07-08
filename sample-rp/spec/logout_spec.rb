require 'spec_helper'
require_relative '../app'

RSpec.describe 'Logout Flow', type: :feature do
  include Capybara::DSL
  
  before do
    Capybara.app = Sinatra::Application
  end
  
  describe 'GET /logout' do
    context 'when user is logged in' do
      it 'clears user session and redirects to home page' do
        # Test 22: Logout - Session cleanup
        user_info = {
          sub: 'user123',
          name: 'Test User',
          email: 'user@example.com'
        }
        
        page.set_rack_session(
          user_info: user_info,
          access_token: 'access_token_123',
          refresh_token: 'refresh_token_456'
        )
        
        visit '/logout'
        
        expect(current_path).to eq('/')
        expect(page).to have_content('You have been logged out successfully')
        expect(page).to have_link('Login with OAuth2')
        expect(page).not_to have_content('Welcome, Test User!')
        
        # Verify session is cleared
        session = page.rack_session
        expect(session[:user_info]).to be_nil
        expect(session[:access_token]).to be_nil
        expect(session[:refresh_token]).to be_nil
      end
      
      it 'clears all OAuth2-related session data' do
        page.set_rack_session(
          user_info: { sub: 'user123' },
          access_token: 'access_token_123',
          refresh_token: 'refresh_token_456',
          oauth_state: 'state_value',
          code_verifier: 'verifier_value',
          id_token: 'id_token_value'
        )
        
        visit '/logout'
        
        session = page.rack_session
        expect(session[:user_info]).to be_nil
        expect(session[:access_token]).to be_nil
        expect(session[:refresh_token]).to be_nil
        expect(session[:oauth_state]).to be_nil
        expect(session[:code_verifier]).to be_nil
        expect(session[:id_token]).to be_nil
      end
      
      it 'preserves non-OAuth session data' do
        page.set_rack_session(
          user_info: { sub: 'user123' },
          access_token: 'access_token_123',
          csrf_token: 'csrf_value',
          flash_messages: ['Important message'],
          user_preferences: { theme: 'dark' }
        )
        
        visit '/logout'
        
        session = page.rack_session
        expect(session[:user_info]).to be_nil
        expect(session[:access_token]).to be_nil
        # Non-OAuth data should be preserved
        expect(session[:csrf_token]).to eq('csrf_value')
        expect(session[:flash_messages]).to eq(['Important message'])
        expect(session[:user_preferences]).to eq({ theme: 'dark' })
      end
    end
    
    context 'when user is not logged in' do
      it 'redirects to home page with appropriate message' do
        visit '/logout'
        
        expect(current_path).to eq('/')
        expect(page).to have_content('You are not currently logged in')
        expect(page).to have_link('Login with OAuth2')
      end
    end
  end
  
  describe 'POST /logout' do
    it 'supports POST method for logout (CSRF protection)' do
      user_info = { sub: 'user123', name: 'Test User' }
      page.set_rack_session(user_info: user_info)
      
      # Simulate form submission
      page.driver.submit :post, '/logout', {}
      
      expect(current_path).to eq('/')
      expect(page).to have_content('You have been logged out successfully')
      
      session = page.rack_session
      expect(session[:user_info]).to be_nil
    end
    
    it 'includes CSRF token validation for POST requests' do
      user_info = { sub: 'user123', name: 'Test User' }
      csrf_token = 'valid_csrf_token'
      
      page.set_rack_session(
        user_info: user_info,
        csrf_token: csrf_token
      )
      
      # Submit with valid CSRF token
      page.driver.submit :post, '/logout', { csrf_token: csrf_token }
      
      expect(current_path).to eq('/')
      expect(page).to have_content('You have been logged out successfully')
    end
    
    it 'rejects POST requests with invalid CSRF token' do
      user_info = { sub: 'user123', name: 'Test User' }
      csrf_token = 'valid_csrf_token'
      
      page.set_rack_session(
        user_info: user_info,
        csrf_token: csrf_token
      )
      
      # Submit with invalid CSRF token
      page.driver.submit :post, '/logout', { csrf_token: 'invalid_token' }
      
      expect(page.status_code).to eq(403)
      expect(page).to have_content('CSRF token validation failed')
      
      # User should still be logged in
      session = page.rack_session
      expect(session[:user_info]).not_to be_nil
    end
  end
  
  describe 'logout with RP-Initiated Logout (OIDC)' do
    it 'supports RP-initiated logout with id_token_hint' do
      user_info = { sub: 'user123', name: 'Test User' }
      id_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
      
      page.set_rack_session(
        user_info: user_info,
        id_token: id_token
      )
      
      visit '/logout?rp_initiated=true'
      
      # Should redirect to authorization server's end_session_endpoint
      expect(current_url).to include('localhost:9292/logout')
      expect(current_url).to include('id_token_hint=')
      expect(current_url).to include('post_logout_redirect_uri=')
    end
    
    it 'includes post_logout_redirect_uri in RP-initiated logout' do
      user_info = { sub: 'user123', name: 'Test User' }
      id_token = 'test_id_token'
      
      page.set_rack_session(
        user_info: user_info,
        id_token: id_token
      )
      
      visit '/logout?rp_initiated=true'
      
      expect(current_url).to include('post_logout_redirect_uri=http%3A//localhost%3A4567/logout/callback')
    end
    
    it 'falls back to local logout when no id_token is available' do
      user_info = { sub: 'user123', name: 'Test User' }
      
      page.set_rack_session(user_info: user_info)
      # No id_token in session
      
      visit '/logout?rp_initiated=true'
      
      expect(current_path).to eq('/')
      expect(page).to have_content('You have been logged out successfully')
      expect(page).to have_content('Note: Single sign-out was not available')
    end
  end
  
  describe 'GET /logout/callback' do
    it 'handles post-logout redirect from authorization server' do
      visit '/logout/callback'
      
      expect(current_path).to eq('/')
      expect(page).to have_content('You have been logged out from all applications')
      expect(page).to have_link('Login with OAuth2')
    end
    
    it 'handles logout errors from authorization server' do
      visit '/logout/callback?error=invalid_request&error_description=Invalid%20logout%20request'
      
      expect(current_path).to eq('/')
      expect(page).to have_content('Logout completed with warnings')
      expect(page).to have_content('invalid_request')
      expect(page).to have_content('Invalid logout request')
    end
  end
  
  describe 'logout security considerations' do
    it 'regenerates session ID after logout' do
      user_info = { sub: 'user123', name: 'Test User' }
      page.set_rack_session(user_info: user_info)
      
      old_session_id = page.rack_session_wrapper.session_id
      
      visit '/logout'
      
      new_session_id = page.rack_session_wrapper.session_id
      expect(new_session_id).not_to eq(old_session_id)
    end
    
    it 'sets cache-control headers to prevent caching of logout response' do
      user_info = { sub: 'user123', name: 'Test User' }
      page.set_rack_session(user_info: user_info)
      
      visit '/logout'
      
      response_headers = page.response_headers
      expect(response_headers['Cache-Control']).to include('no-cache')
      expect(response_headers['Cache-Control']).to include('no-store')
      expect(response_headers['Pragma']).to eq('no-cache')
    end
    
    it 'includes security headers in logout response' do
      user_info = { sub: 'user123', name: 'Test User' }
      page.set_rack_session(user_info: user_info)
      
      visit '/logout'
      
      response_headers = page.response_headers
      expect(response_headers['X-Frame-Options']).to eq('DENY')
      expect(response_headers['X-Content-Type-Options']).to eq('nosniff')
    end
  end
end