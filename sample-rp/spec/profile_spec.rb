require 'spec_helper'
require_relative '../app'

RSpec.describe 'User Profile Display', type: :feature do
  include Capybara::DSL
  
  before do
    Capybara.app = Sinatra::Application
  end
  
  describe 'GET /profile' do
    context 'when user is logged in' do
      it 'displays user profile information' do
        # Test 21: Profile display - User info display
        user_info = {
          sub: 'user123',
          name: 'Test User',
          email: 'user@example.com',
          preferred_username: 'testuser',
          given_name: 'Test',
          family_name: 'User',
          picture: 'https://example.com/avatar.jpg'
        }
        
        page.set_rack_session(user_info: user_info)
        
        visit '/profile'
        
        expect(page).to have_content('User Profile')
        expect(page).to have_content('Test User')
        expect(page).to have_content('user@example.com')
        expect(page).to have_content('testuser')
        expect(page).to have_content('user123')
      end
      
      it 'displays optional profile fields when available' do
        user_info = {
          sub: 'user123',
          name: 'Test User',
          email: 'user@example.com',
          given_name: 'Test',
          family_name: 'User',
          birthdate: '1990-01-01',
          phone_number: '+1-555-123-4567',
          address: {
            street_address: '123 Main St',
            locality: 'Anytown',
            region: 'CA',
            postal_code: '12345',
            country: 'US'
          }
        }
        
        page.set_rack_session(user_info: user_info)
        
        visit '/profile'
        
        expect(page).to have_content('Given Name: Test')
        expect(page).to have_content('Family Name: User')
        expect(page).to have_content('Birthdate: 1990-01-01')
        expect(page).to have_content('Phone: +1-555-123-4567')
        expect(page).to have_content('Address:')
        expect(page).to have_content('123 Main St')
        expect(page).to have_content('Anytown, CA 12345')
      end
      
      it 'handles missing optional fields gracefully' do
        user_info = {
          sub: 'user123',
          name: 'Test User'
          # Missing email, given_name, family_name, etc.
        }
        
        page.set_rack_session(user_info: user_info)
        
        visit '/profile'
        
        expect(page).to have_content('User Profile')
        expect(page).to have_content('Test User')
        expect(page).to have_content('Subject ID: user123')
        expect(page).not_to have_content('Email:')
        expect(page).not_to have_content('Given Name:')
      end
      
      it 'displays profile picture when available' do
        user_info = {
          sub: 'user123',
          name: 'Test User',
          picture: 'https://example.com/avatar.jpg'
        }
        
        page.set_rack_session(user_info: user_info)
        
        visit '/profile'
        
        expect(page).to have_css('img[src="https://example.com/avatar.jpg"]')
        expect(page).to have_css('img[alt="Profile Picture"]')
      end
      
      it 'includes navigation links' do
        user_info = { sub: 'user123', name: 'Test User' }
        page.set_rack_session(user_info: user_info)
        
        visit '/profile'
        
        expect(page).to have_link('Home', href: '/')
        expect(page).to have_link('Logout', href: '/logout')
      end
      
      it 'displays raw user info in development mode' do
        # Mock development environment
        allow(Sinatra::Application.settings).to receive(:development?).and_return(true)
        
        user_info = {
          sub: 'user123',
          name: 'Test User',
          email: 'user@example.com',
          custom_claim: 'custom_value'
        }
        
        page.set_rack_session(user_info: user_info)
        
        visit '/profile'
        
        expect(page).to have_content('Raw User Info (Development)')
        expect(page).to have_content('"custom_claim": "custom_value"')
        expect(page).to have_css('pre') # JSON should be in a <pre> tag
      end
    end
    
    context 'when user is not logged in' do
      it 'redirects to login page' do
        visit '/profile'
        
        expect(current_path).to eq('/login')
      end
      
      it 'shows flash message about login requirement' do
        visit '/profile'
        
        follow_redirect!
        expect(page).to have_content('Please log in to view your profile')
      end
    end
  end
  
  describe 'profile data formatting' do
    it 'formats address object as readable text' do
      user_info = {
        sub: 'user123',
        name: 'Test User',
        address: {
          street_address: '123 Main Street',
          locality: 'San Francisco',
          region: 'California',
          postal_code: '94105',
          country: 'United States'
        }
      }
      
      page.set_rack_session(user_info: user_info)
      
      visit '/profile'
      
      # Should format address nicely
      expect(page).to have_content('123 Main Street')
      expect(page).to have_content('San Francisco, California 94105')
      expect(page).to have_content('United States')
    end
    
    it 'formats timestamps in human-readable format' do
      user_info = {
        sub: 'user123',
        name: 'Test User',
        updated_at: '1516239022'  # Unix timestamp
      }
      
      page.set_rack_session(user_info: user_info)
      
      visit '/profile'
      
      # Should format timestamp as readable date
      expect(page).to have_content('Updated: ')
      expect(page).to have_content('2018')  # Should contain year from timestamp
    end
    
    it 'handles boolean values appropriately' do
      user_info = {
        sub: 'user123',
        name: 'Test User',
        email_verified: true,
        phone_number_verified: false
      }
      
      page.set_rack_session(user_info: user_info)
      
      visit '/profile'
      
      expect(page).to have_content('Email Verified: Yes')
      expect(page).to have_content('Phone Verified: No')
    end
  end
  
  describe 'accessibility and usability' do
    it 'includes proper semantic HTML structure' do
      user_info = { sub: 'user123', name: 'Test User' }
      page.set_rack_session(user_info: user_info)
      
      visit '/profile'
      
      expect(page).to have_css('h1', text: 'User Profile')
      expect(page).to have_css('dl')  # Definition list for user info
      expect(page).to have_css('dt')  # Definition terms (labels)
      expect(page).to have_css('dd')  # Definition descriptions (values)
    end
    
    it 'includes proper ARIA labels for screen readers' do
      user_info = { sub: 'user123', name: 'Test User' }
      page.set_rack_session(user_info: user_info)
      
      visit '/profile'
      
      expect(page).to have_css('[aria-label]')
      expect(page).to have_css('main[role="main"]')
    end
  end
end