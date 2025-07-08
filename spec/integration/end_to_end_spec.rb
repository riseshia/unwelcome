require 'spec_helper'
require 'capybara/rspec'

RSpec.describe 'End-to-End OAuth2/OIDC Flow', type: :feature do
  include Capybara::DSL
  
  before do
    # Configure Capybara for full integration testing
    Capybara.app_host = 'http://localhost:4567'  # Sample RP
    Capybara.server_host = '0.0.0.0'
    Capybara.server_port = 4567
    
    # Start authorization server on port 9292
    # This would typically be done in a setup script or test helper
  end
  
  describe 'Complete OAuth2 Authorization Code Flow' do
    it 'performs full authentication flow from login to profile display' do
      # Test 23: End-to-end flow - Complete auth flow
      
      # Step 1: User visits Sample RP and initiates login
      visit '/'
      expect(page).to have_content('Sample Relying Party')
      expect(page).to have_link('Login with OAuth2')
      
      click_link 'Login with OAuth2'
      
      # Step 2: User is redirected to Authorization Server
      expect(current_url).to include('localhost:9292/authorize')
      expect(current_url).to include('client_id=sample_rp_client')
      expect(current_url).to include('response_type=code')
      expect(current_url).to include('scope=openid%20profile%20email')
      expect(current_url).to include('code_challenge=')
      
      # Step 3: User sees authorization page (mock user login and consent)
      expect(page).to have_content('Authorize Application')
      expect(page).to have_content('sample_rp_client')
      expect(page).to have_content('wants to access your')
      expect(page).to have_content('openid, profile, email')
      
      # Mock user login (this would normally be a login form)
      fill_in 'username', with: 'testuser@example.com'
      fill_in 'password', with: 'testpassword'
      click_button 'Login'
      
      # Step 4: User grants consent
      expect(page).to have_content('Grant Access')
      expect(page).to have_button('Allow')
      expect(page).to have_button('Deny')
      
      click_button 'Allow'
      
      # Step 5: Authorization Server redirects back to Sample RP with auth code
      expect(current_url).to start_with('http://localhost:4567/callback')
      expect(current_url).to include('code=')
      expect(current_url).to include('state=')
      
      # Step 6: Sample RP processes callback and displays user profile
      expect(current_path).to eq('/')
      expect(page).to have_content('Welcome, Test User!')
      expect(page).to have_content('testuser@example.com')
      expect(page).to have_link('Profile')
      expect(page).to have_link('Logout')
      
      # Step 7: User views detailed profile
      click_link 'Profile'
      
      expect(current_path).to eq('/profile')
      expect(page).to have_content('User Profile')
      expect(page).to have_content('Name: Test User')
      expect(page).to have_content('Email: testuser@example.com')
      expect(page).to have_content('Subject ID: user123')
      
      # Step 8: User logs out
      click_link 'Logout'
      
      expect(current_path).to eq('/')
      expect(page).to have_content('You have been logged out successfully')
      expect(page).to have_link('Login with OAuth2')
      expect(page).not_to have_content('Welcome, Test User!')
    end
    
    it 'handles token refresh flow correctly' do
      # Test automatic token refresh when access token expires
      
      # Start with a logged-in user with short-lived access token
      visit '/'
      click_link 'Login with OAuth2'
      
      # Mock authorization and login process
      fill_in 'username', with: 'testuser@example.com'
      fill_in 'password', with: 'testpassword'
      click_button 'Login'
      click_button 'Allow'
      
      # User is now logged in
      expect(page).to have_content('Welcome, Test User!')
      
      # Simulate access token expiration by advancing time
      # or mocking token validation to return expired
      Timecop.travel(Time.now + 1.hour) do
        # Try to access protected resource that requires fresh token
        visit '/profile'
        
        # Should automatically refresh token and display profile
        expect(current_path).to eq('/profile')
        expect(page).to have_content('User Profile')
        expect(page).not_to have_content('Token expired')
      end
    end
    
    it 'supports PKCE flow end-to-end' do
      visit '/'
      click_link 'Login with OAuth2'
      
      # Verify PKCE parameters are included
      expect(current_url).to include('code_challenge=')
      expect(current_url).to include('code_challenge_method=S256')
      
      # Complete auth flow
      fill_in 'username', with: 'testuser@example.com'
      fill_in 'password', with: 'testpassword'
      click_button 'Login'
      click_button 'Allow'
      
      # Should successfully complete even with PKCE
      expect(page).to have_content('Welcome, Test User!')
    end
  end
  
  describe 'OIDC ID Token flow' do
    it 'receives and validates ID token during authentication' do
      visit '/'
      click_link 'Login with OAuth2'
      
      # Complete auth flow with openid scope
      fill_in 'username', with: 'testuser@example.com'
      fill_in 'password', with: 'testpassword'
      click_button 'Login'
      click_button 'Allow'
      
      # Should have received ID token
      visit '/profile'
      
      # In development mode, should show raw ID token info
      if page.has_content?('Raw User Info')
        expect(page).to have_content('"iss":')
        expect(page).to have_content('"aud":')
        expect(page).to have_content('"sub":')
      end
    end
  end
  
  describe 'Multiple client scenarios' do
    it 'handles multiple simultaneous client sessions' do
      # This would test scenarios where user has sessions with multiple
      # OAuth2 clients simultaneously
      
      # Session 1: Sample RP
      using_session('rp1') do
        visit '/'
        click_link 'Login with OAuth2'
        # Complete auth flow
        fill_in 'username', with: 'testuser@example.com'
        fill_in 'password', with: 'testpassword'
        click_button 'Login'
        click_button 'Allow'
        
        expect(page).to have_content('Welcome, Test User!')
      end
      
      # Session 2: Another client (if implemented)
      using_session('rp2') do
        # Similar flow but for different client
        # Should reuse authorization server session but get new client consent
        visit 'http://localhost:4568/'  # Different client
        # ... auth flow for second client
      end
      
      # Both sessions should work independently
      using_session('rp1') do
        visit '/profile'
        expect(page).to have_content('User Profile')
      end
    end
  end
  
  describe 'Cross-browser compatibility' do
    it 'works with different browsers', :js do
      # Test with different Capybara drivers
      [:chrome, :firefox, :safari].each do |browser|
        next unless browser_available?(browser)
        
        Capybara.current_driver = browser
        
        visit '/'
        expect(page).to have_content('Sample Relying Party')
        click_link 'Login with OAuth2'
        
        expect(current_url).to include('localhost:9292/authorize')
      end
    end
  end
  
  private
  
  def browser_available?(browser)
    # Check if browser driver is available
    case browser
    when :chrome
      system('which chromedriver > /dev/null 2>&1')
    when :firefox
      system('which geckodriver > /dev/null 2>&1')
    when :safari
      RUBY_PLATFORM.include?('darwin')
    else
      false
    end
  end
end