require 'spec_helper'
require 'utils/pkce'

RSpec.describe Utils::PKCE do
  let(:pkce) { described_class.new }
  
  describe '#generate_code_verifier' do
    it 'generates code_verifier for PKCE flow' do
      # Test 13: PKCE client - code_verifier/code_challenge generation
      code_verifier = pkce.generate_code_verifier
      
      expect(code_verifier).to be_a(String)
      expect(code_verifier.length).to be_between(43, 128)
      expect(code_verifier).to match(/\A[a-zA-Z0-9_.-]+\z/)
    end
    
    it 'generates different code_verifiers on each call' do
      code_verifier1 = pkce.generate_code_verifier
      code_verifier2 = pkce.generate_code_verifier
      
      expect(code_verifier1).not_to eq(code_verifier2)
    end
    
    it 'generates code_verifier with custom length' do
      length = 64
      code_verifier = pkce.generate_code_verifier(length)
      
      expect(code_verifier.length).to eq(length)
    end
  end
  
  describe '#generate_code_challenge' do
    it 'generates code_challenge using S256 method' do
      code_verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      
      code_challenge = pkce.generate_code_challenge(code_verifier, 'S256')
      
      expect(code_challenge).to eq('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
    end
    
    it 'generates code_challenge using plain method' do
      code_verifier = 'test_code_verifier'
      
      code_challenge = pkce.generate_code_challenge(code_verifier, 'plain')
      
      expect(code_challenge).to eq(code_verifier)
    end
    
    it 'defaults to S256 method when method not specified' do
      code_verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      
      code_challenge = pkce.generate_code_challenge(code_verifier)
      
      expect(code_challenge).to eq('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
    end
    
    it 'raises error for unsupported challenge method' do
      code_verifier = 'test_code_verifier'
      
      expect {
        pkce.generate_code_challenge(code_verifier, 'unsupported')
      }.to raise_error(Utils::PKCE::UnsupportedMethod)
    end
  end
  
  describe '#create_pkce_pair' do
    it 'creates code_verifier and code_challenge pair' do
      pkce_pair = pkce.create_pkce_pair
      
      expect(pkce_pair).to have_key(:code_verifier)
      expect(pkce_pair).to have_key(:code_challenge)
      expect(pkce_pair).to have_key(:code_challenge_method)
      expect(pkce_pair[:code_challenge_method]).to eq('S256')
    end
    
    it 'creates valid PKCE pair that can be verified' do
      pkce_pair = pkce.create_pkce_pair
      
      # Verify the challenge matches the verifier
      expected_challenge = pkce.generate_code_challenge(
        pkce_pair[:code_verifier], 
        pkce_pair[:code_challenge_method]
      )
      
      expect(pkce_pair[:code_challenge]).to eq(expected_challenge)
    end
  end
end