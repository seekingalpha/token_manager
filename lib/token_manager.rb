# frozen_string_literal: true

require_relative 'token_manager/version'
require 'jwt'
require 'securerandom'
require 'curb'
require 'active_support/all'
require_relative 'token_manager/faraday_middleware'

class TokenManager
  class RetrievePublicKeyError < StandardError; end
  ALGO = 'RS256'

  def self.token_from(headers)
    headers['Authorization']&.match(/Token token="(\S+)"/)&.[](1) ||
      headers['Authorization']&.match(/Bearer (\S+)/)&.[](1)
  end

  def initialize(options)
    options = options.deep_stringify_keys
    @service_name = options['service_name'] || raise(ArgumentError, '`service_name` is required')
    @trusted_issuers = options['trusted_issuers'] || {}
    @token_ttl = options['token_ttl']
    @public_key_ttl = options['public_key_ttl'] || 1.month
    @old_key_ttl = options['old_key_ttl'] || 1.week
  end

  def encode(payload)
    payload = payload.stringify_keys
    raise(ArgumentError, '`aud` is required') unless payload.key?('aud')

    raise(ArgumentError, '`exp` claim or `token_ttl` config option is required') if !payload.key?('exp') && !@token_ttl

    payload.reverse_merge!(exp: @token_ttl.seconds.from_now.to_i) if @token_ttl

    payload = payload.merge(iss: @service_name)
    ::JWT.encode(payload, private_key, ALGO, { kid: key_id })
  end

  def decode(jwt, options = {})
    options = options.merge(
      algorithm: ALGO,
      required_claims: ['exp', 'iss', 'aud'],
      verify_iss: true,
      iss: @trusted_issuers.keys,
      verify_aud: true,
      aud: @service_name
    )
    ::JWT.decode(jwt, nil, true, options) do |header, payload|
      OpenSSL::PKey::RSA.new(issuer_public_key(iss: payload['iss'], kid: header['kid']))
    end
  end

  def public_key(kid = key_id)
    @public_key ||= {}
    @public_key[kid.to_s] ||= with_redis { |redis| redis.get(cache_key(:public_key, kid)) }
  end

  def generate_private_key(expire_current_token: true)
    rsa_private = OpenSSL::PKey::RSA.generate(2048)
    rsa_public = rsa_private.public_key
    next_key_id = SecureRandom.uuid
    with_redis do |redis|
      redis.multi do |multi|
        # set new token
        multi.set(cache_key(:private_key, next_key_id), rsa_private.to_pem)
        multi.set(cache_key(:public_key, next_key_id), rsa_public.to_pem)
        multi.set(cache_key(:key_id), next_key_id)
        if expire_current_token
          # expire current token
          multi.expire(cache_key(:private_key, key_id), @old_key_ttl)
          multi.expire(cache_key(:public_key, key_id), @old_key_ttl)
        end
      end
    end
    # drop memoization
    @key_id = next_key_id
    @private_key = rsa_private

    rsa_private
  end

  def key_id
    @key_id ||= with_redis do |c|
      c.get(cache_key(:key_id)) ||
        generate_private_key(expire_current_token: false) && c.get(cache_key(:key_id))
    end
  end

  private

  def issuer_public_key(iss:, kid:)
    @issuer_public_key ||= {}
    @issuer_public_key[iss] ||= {}
    @issuer_public_key[iss][kid] ||= if iss == @service_name
                                       public_key(kid)
                                     else
                                       redis_fetch(cache_key(:issuer_public_key, iss, kid), ex: @public_key_ttl) do
                                         retrieve_issuer_key(iss, kid)
                                       end
                                     end
  end

  def retrieve_issuer_key(iss, kid)
    url = @trusted_issuers.dig(iss, 'url')
    raise(RetrievePublicKeyError, "Add trusted_issuers: { url: 'https://my_app.com/public_key_url' }") unless url

    response = Curl.get(@trusted_issuers.dig(iss, 'url'), kid: kid) do |c|
      c.headers.merge!('User-Agent' => @service_name)
    end
    unless response.response_code.in?(200..299)
      raise(RetrievePublicKeyError,
            "Can't retrieve public_key from #{response.url}. Response code: #{response.response_code}")
    end

    parsed = JSON.parse(response.body)
    parsed['public_key']
  end

  def redis_fetch(key, options = {})
    res = with_redis { |redis| redis.get(key) }
    return res if res

    res = yield
    with_redis { |redis| redis.set(key, res, **options) }
    res
  end

  def private_key
    @private_key ||= OpenSSL::PKey::RSA.new(with_redis do |c|
                                              c.get(cache_key(:private_key, key_id)) || generate_private_key
                                            end)
  end

  def cache_key(*args)
    [:token_manager, @service_name, *args].join(':')
  end

  def with_redis
    raise NotImplementedError
  end
end
