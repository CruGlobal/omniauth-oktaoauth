# frozen_string_literal: true

require 'spec_helper'

describe OmniAuth::Strategies::Oktaoauth do

  let(:base_url) { 'https://your-org.okta.com' }
  let(:strategy_options) do
    {
      client_options: {
        site:          base_url,
        authorize_url: "#{base_url}/oauth2/v1/authorize",
        token_url:     "#{base_url}/oauth2/v1/token"
      }
    }
  end

  subject { described_class.new({}, 'client_id', 'client_secret', strategy_options) }

  describe '#client' do
    it 'has the configured site' do
      expect(subject.client.site).to eq(base_url)
    end

    context '.client_options' do
      it 'has the configured site' do
        expect(subject.options.client_options.site).to \
        eq(base_url)
      end

      it 'has the configured authorize url' do
        expect(subject.options.client_options.authorize_url).to \
        eq("#{base_url}/oauth2/v1/authorize")
      end

      it 'has the configured token url' do
        expect(subject.options.client_options.token_url).to \
        eq("#{base_url}/oauth2/v1/token")
      end

      it 'has default response_type' do
        expect(subject.options.client_options.response_type).to \
        eq('id_token')
      end
    end
  end

  describe '#callback_path' do
    it 'has the correct callback path' do
      expect(subject.callback_path).to \
      eq('/auth/oktaoauth/callback')
    end
  end

  describe '#uid' do
    before :each do
      allow(subject).to receive(:raw_info) { { 'sub' => 'uid' } }
    end

    it 'returns the id from raw_info' do
      expect(subject.uid).to eq('uid')
    end
  end

  describe '#info' do
    before :each do
      allow(subject).to receive(:raw_info) { {} }
    end

    context 'has the necessary fields' do
      it { expect(subject.info).to have_key :name }
      it { expect(subject.info).to have_key :email }
      it { expect(subject.info).to have_key :first_name }
      it { expect(subject.info).to have_key :last_name }
      it { expect(subject.info).to have_key :image }
    end
  end

  describe 'extra' do
    before :each do
      allow(subject).to receive(:raw_info) { { :foo => 'bar' } }
      subject.access_token = OAuth2::AccessToken.new(
        subject.client,
        JWT.encode({ 'sub' => 'uid' }, nil, 'none'),
        'id_token' => JWT.encode({ 'sub' => 'uid' }, nil, 'none')
      )
    end

    it { expect(subject.extra[:raw_info]).to eq({ :foo => 'bar' }) }
  end

  describe '#authorize_params' do
    let(:strategy_options) { super().merge(redirect_uri: 'https://app.example/auth/oktaoauth/callback') }
    let(:session) { {} }

    before { allow(subject).to receive(:session).and_return(session) }

    it 'stores the nonce it sends' do
      params = subject.authorize_params

      expect(params[:nonce]).to be_a(String)
      expect(session['omniauth.nonce']).to eq(params[:nonce])
    end

    context 'when pkce is on' do
      let(:strategy_options) { super().merge(pkce: true) }

      it 'sends a code challenge along with the nonce' do
        params = subject.authorize_params

        expect(params[:code_challenge]).to be_a(String)
        expect(params[:code_challenge_method]).to eq('S256')
        expect(params[:nonce]).to eq(session['omniauth.nonce'])
        expect(session['omniauth.pkce.verifier']).to be_a(String)
      end
    end
  end

  describe '#callback_phase' do
    let(:app_calls) { [] }
    let(:app) { ->(env) { app_calls << env; [200, {}, ['signed in']] } }
    let(:failures) { [] }
    let(:strategy) { described_class.new(app, 'client_id', 'client_secret', strategy_options) }

    let(:state) { 'state-123' }
    let(:nonce) { 'nonce-abc' }
    let(:session) { { 'omniauth.state' => state, 'omniauth.nonce' => nonce } }
    let(:id_token_nonce) { nonce }
    let(:id_token) { JWT.encode({ 'sub' => 'uid', 'nonce' => id_token_nonce }, nil, 'none') }
    let(:token_response_params) { { 'id_token' => id_token } }
    let(:client) { OAuth2::Client.new('client_id', 'client_secret', site: base_url) }
    let(:token_response) do
      OAuth2::AccessToken.new(client, JWT.encode({ 'sub' => 'uid' }, nil, 'none'), token_response_params)
    end
    let(:callback_params) { { 'code' => 'auth-code', 'state' => state } }
    let(:env) do
      Rack::MockRequest.env_for(
        "/auth/oktaoauth/callback?#{Rack::Utils.build_query(callback_params)}",
        'rack.session' => session
      )
    end

    around do |example|
      test_mode = OmniAuth.config.test_mode
      on_failure = OmniAuth.config.on_failure
      OmniAuth.config.test_mode = false
      OmniAuth.config.on_failure = lambda do |failure_env|
        failures << failure_env['omniauth.error.type']
        OmniAuth::FailureEndpoint.call(failure_env)
      end
      begin
        example.run
      ensure
        OmniAuth.config.test_mode = test_mode
        OmniAuth.config.on_failure = on_failure
      end
    end

    before do
      allow(strategy).to receive(:client).and_return(client)
      allow(client.auth_code).to receive(:get_token).and_return(token_response)
      allow(strategy).to receive(:raw_info).and_return('sub' => 'uid', 'email' => 'user@example.com')
    end

    def run_callback
      strategy.call!(env)
    end

    shared_examples 'an invalid nonce' do
      it 'fails with :invalid_nonce without running the app callback' do
        expect(strategy).to receive(:fail!)
          .with(:invalid_nonce, kind_of(described_class::InvalidNonce))
          .and_call_original

        status, headers, = run_callback

        expect(app_calls).to be_empty
        expect(env).not_to have_key('omniauth.auth')
        expect(failures).to eq([:invalid_nonce])
        expect(status).to eq(302)
        expect(headers['Location']).to eq('/auth/failure?message=invalid_nonce&strategy=oktaoauth')
      end
    end

    context 'when the id_token nonce matches the stored nonce' do
      it 'runs the app callback with the auth hash' do
        status, = run_callback

        expect(status).to eq(200)
        expect(failures).to be_empty
        expect(app_calls.size).to eq(1)
        expect(env['omniauth.auth']['uid']).to eq('uid')
        expect(env['omniauth.auth']['extra']['id_token']).to eq(id_token)
      end

      it 'removes the stored nonce from the session' do
        run_callback

        expect(session).not_to have_key('omniauth.nonce')
      end
    end

    context 'when the id_token nonce does not match the stored nonce' do
      let(:id_token_nonce) { 'some-other-nonce' }

      include_examples 'an invalid nonce'

      it 'removes the stored nonce from the session' do
        run_callback

        expect(session).not_to have_key('omniauth.nonce')
      end
    end

    context 'when skip_jwt is set and the nonce does not match' do
      let(:strategy_options) { super().merge(skip_jwt: true) }
      let(:id_token_nonce) { 'some-other-nonce' }

      include_examples 'an invalid nonce'
    end

    context 'when the session has no stored nonce' do
      let(:session) { { 'omniauth.state' => state } }

      include_examples 'an invalid nonce'
    end

    context 'when the token response has no id_token' do
      let(:token_response_params) { {} }

      include_examples 'an invalid nonce'
    end

    context 'when the id_token cannot be decoded' do
      let(:id_token) { 'not-a-jwt' }

      include_examples 'an invalid nonce'
    end

    context 'when the id_token payload is not a JSON object' do
      let(:id_token) { JWT.encode([1], nil, 'none') }

      include_examples 'an invalid nonce'
    end

    context 'when pkce is on' do
      let(:strategy_options) { super().merge(pkce: true) }
      let(:session) { { 'omniauth.state' => state, 'omniauth.nonce' => nonce, 'omniauth.pkce.verifier' => 'the-verifier' } }

      it 'sends the stored code verifier and runs the app callback' do
        status, = run_callback

        expect(status).to eq(200)
        expect(failures).to be_empty
        expect(app_calls.size).to eq(1)
        expect(client.auth_code).to have_received(:get_token)
          .with('auth-code', hash_including(code_verifier: 'the-verifier'), anything)
      end
    end

    context 'when the state does not match' do
      let(:callback_params) { { 'code' => 'auth-code', 'state' => 'forged-state' } }

      it 'returns the csrf_detected failure without raising' do
        response = nil
        expect { response = run_callback }.not_to raise_error

        expect(failures).to eq([:csrf_detected])
        expect(env['omniauth.error']).to be_a(OmniAuth::Strategies::OAuth2::CallbackError)
        expect(response[0]).to eq(302)
        expect(response[1]['Location']).to eq('/auth/failure?message=csrf_detected&strategy=oktaoauth')
        expect(app_calls).to be_empty
        expect(client.auth_code).not_to have_received(:get_token)
      end
    end

    context 'when Okta returns an error' do
      let(:callback_params) { { 'error' => 'access_denied', 'state' => state } }

      it 'returns the provider error failure without raising' do
        expect { run_callback }.not_to raise_error

        expect(failures).to eq([:access_denied])
        expect(app_calls).to be_empty
      end
    end
  end
end
