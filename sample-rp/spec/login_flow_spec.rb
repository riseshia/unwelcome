require 'spec_helper'
require_relative '../app'

RSpec.describe 'Login Flow', type: :feature do
  include Capybara::DSL
  
  before do
    Capybara.app = Sinatra::Application
  end
  
  describe 'GET /' do
    it 'displays login page with OAuth2 login button' do
      # Test 19: Login page - Login button and redirect
      visit '/'
      
      expect(page).to have_content('Sample Relying Party')
      expect(page).to have_content('Welcome to OAuth2/OIDC Demo')
      expect(page).to have_link('Login with OAuth2', href: '/login')
    end
    
    it 'shows user info when already logged in' do
      # Mock session with user data
      page.set_rack_session(user_info: {
        sub: 'user123',
        name: 'Test User',
        email: 'user@example.com'
      })
      
      visit '/'
      
      expect(page).to have_content('Welcome, Test User!')
      expect(page).to have_content('user@example.com')
      expect(page).to have_link('Logout', href: '/logout')
      expect(page).not_to have_link('Login with OAuth2')
    end
  end
  
  describe 'GET /login' do
    it 'redirects to OAuth2 authorization server' do
      visit '/login'
      
      expect(current_url).to include('localhost:9292/authorize')
      expect(current_url).to include('client_id=sample_rp_client')
      expect(current_url).to include('response_type=code')
      expect(current_url).to include('scope=openid%20profile%20email')
      expect(current_url).to include('redirect_uri=')
      expect(current_url).to include('state=')
    end
    
    it 'includes PKCE parameters in authorization URL' do
      visit '/login'
      
      expect(current_url).to include('code_challenge=')
      expect(current_url).to include('code_challenge_method=S256')
    end
    
    it 'stores state and code_verifier in session' do
      visit '/login'
      
      # Check that session contains required PKCE parameters
      session = page.rack_session
      expect(session[:oauth_state]).not_to be_nil
      expect(session[:code_verifier]).not_to be_nil
      expect(session[:oauth_state].length).to be > 10
      expect(session[:code_verifier].length).to be_between(43, 128)
    end
    
    it 'generates unique state on each login attempt' do
      visit '/login'
      first_state = page.rack_session[:oauth_state]
      
      visit '/login'
      second_state = page.rack_session[:oauth_state]
      
      expect(first_state).not_to eq(second_state)
    end
  end
  
  describe 'session management' do
    it 'clears old session data on new login attempt' do
      # Set some old session data
      page.set_rack_session(
        user_info: { sub: 'old_user' },
        oauth_state: 'old_state',
        code_verifier: 'old_verifier'
      )
      
      visit '/login'
      
      session = page.rack_session
      expect(session[:user_info]).to be_nil
      expect(session[:oauth_state]).not_to eq('old_state')
      expect(session[:code_verifier]).not_to eq('old_verifier')
    end
  end
  
  describe 'error handling' do
    it 'displays error message for OAuth2 configuration errors' do
      # Mock missing OAuth2 configuration
      allow(ENV).to receive(:[]).with('OAUTH2_CLIENT_ID').and_return(nil)
      
      visit '/login'
      
      expect(page).to have_content('OAuth2 configuration error')
      expect(page).to have_content('CLIENT_ID not configured')
    end
  end
end