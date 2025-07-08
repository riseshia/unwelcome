require 'spec_helper'
require 'oauth2/pkce'

RSpec.describe OAuth2::PKCE do
  let(:pkce) { described_class.new }
  
  describe '#verify_code_challenge' do
    it 'verifies PKCE code_challenge with S256 method' do
      # Test 12: PKCE support - Server-side PKCE validation
      code_verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      code_challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
      code_challenge_method = 'S256'
      
      result = pkce.verify_code_challenge(
        code_verifier: code_verifier,
        code_challenge: code_challenge,
        code_challenge_method: code_challenge_method
      )
      
      expect(result).to be true
    end
    
    it 'verifies PKCE code_challenge with plain method' do
      code_verifier = 'test_code_verifier'
      code_challenge = 'test_code_verifier'
      code_challenge_method = 'plain'
      
      result = pkce.verify_code_challenge(
        code_verifier: code_verifier,
        code_challenge: code_challenge,
        code_challenge_method: code_challenge_method
      )
      
      expect(result).to be true
    end
    
    it 'returns false for invalid code_verifier with S256' do
      code_verifier = 'invalid_code_verifier'
      code_challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
      code_challenge_method = 'S256'
      
      result = pkce.verify_code_challenge(
        code_verifier: code_verifier,
        code_challenge: code_challenge,
        code_challenge_method: code_challenge_method
      )
      
      expect(result).to be false
    end
    
    it 'returns false for invalid code_verifier with plain method' do
      code_verifier = 'invalid_code_verifier'
      code_challenge = 'test_code_verifier'
      code_challenge_method = 'plain'
      
      result = pkce.verify_code_challenge(
        code_verifier: code_verifier,
        code_challenge: code_challenge,
        code_challenge_method: code_challenge_method
      )
      
      expect(result).to be false
    end
    
    it 'raises error for unsupported code_challenge_method' do
      code_verifier = 'test_code_verifier'
      code_challenge = 'test_code_challenge'
      code_challenge_method = 'unsupported'
      
      expect {
        pkce.verify_code_challenge(
          code_verifier: code_verifier,
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method
        )
      }.to raise_error(OAuth2::PKCE::UnsupportedCodeChallengeMethod)
    end
    
    it 'validates code_verifier format' do
      # code_verifier should be 43-128 characters, URL-safe
      short_verifier = 'too_short'
      long_verifier = 'a' * 129
      code_challenge = 'test_challenge'
      code_challenge_method = 'plain'
      
      expect {
        pkce.verify_code_challenge(
          code_verifier: short_verifier,
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method
        )
      }.to raise_error(OAuth2::PKCE::InvalidCodeVerifier)
      
      expect {
        pkce.verify_code_challenge(
          code_verifier: long_verifier,
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method
        )
      }.to raise_error(OAuth2::PKCE::InvalidCodeVerifier)
    end
  end
  
  describe '#generate_code_challenge' do
    it 'generates code_challenge from code_verifier using S256' do
      code_verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      
      code_challenge = pkce.generate_code_challenge(code_verifier, 'S256')
      
      expect(code_challenge).to eq('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
    end
    
    it 'generates code_challenge from code_verifier using plain' do
      code_verifier = 'test_code_verifier'
      
      code_challenge = pkce.generate_code_challenge(code_verifier, 'plain')
      
      expect(code_challenge).to eq(code_verifier)
    end
  end
end