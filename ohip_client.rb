require 'net/http'
require 'uri'
require 'json'
require 'base64'
require 'logger'

# 
#  This class is responsible for managing authentication and API calls to the OHIP system.
#  It provides methods to authenticate, make API calls, and handle token expiration.
#  @author Grant Sayer
# 
class OHIPClient
  attr_reader :token, :token_expires_at
  
  def initialize(client_id, client_secret, api_key, username = nil, password = nil)
    @client_id = client_id
    @client_secret = client_secret
    @api_key = api_key
    @username = username
    @password = password
    @base_url = "https://ca03-mtca1ua-oc.hospitality-api.ap-sydney-1.ocs.oc-test.com"
    @token = nil
    @token_expires_at = nil
    @logger = Logger.new(STDOUT)
    @logger.level = Logger::INFO
  end
  
  # Authenticate with the OHIP API using client credentials
  # @return [Boolean] true if authentication was successful, false otherwise
  # @example
  #   client = OHIPClient.new(client_id, client_secret, api_key)
  #   if client.authenticate
  #     puts "Authentication successful!"
  #   else
  #     puts "Authentication failed."
  #   end
  #
  # @note This method is used to authenticate the client with the OHIP API
  # It will set the token and expiration time if successful
  def authenticate
    uri = URI.parse("#{@base_url}/oauth/v1/tokens")
    request = Net::HTTP::Post.new(uri)
    
    # Set the headers matching the CURL command
    auth_string = Base64.strict_encode64("#{@client_id}:#{@client_secret}")
    request["Authorization"] = "Basic #{auth_string}"
    request["Accept"] = "application/json"
    request["Content-Type"] = "application/x-www-form-urlencoded"
    request["x-app-key"] = @api_key
    
    # Set the request body to match the CURL command
    request.set_form_data({
      "grant_type" => "password",
      "username" => @username || "",
      "password" => @password || "",
      "scope" => ""
    })
    
    response = send_request(uri, request)
    handle_auth_response(response)
  end
  
  # Sends an HTTP request to the specified URI
  # @param uri [URI] the URI to send the request to
  # @param request [Net::HTTPRequest] the HTTP request to send
  # @return [Net::HTTPResponse] the response from the server
  # @example
  #   uri = URI.parse("https://example.com/api")
  #   request = Net::HTTP::Get.new(uri)
  #   response = send_request(uri, request)
  #   puts response.body
  def send_request(uri, request)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    
    begin
      @logger.info("Sending request to #{uri.path}")
      http.request(request)
    rescue StandardError => e
      @logger.error("Error during request: #{e.message}")
      raise "API request failed: #{e.message}"
    end
  end
  
  # Handles the authentication response and sets the token
  # @param response [Net::HTTPResponse] the response from the authentication request
  # @return [Boolean] true if authentication was successful, false otherwise
  # @example
  #   client.handle_auth_response(response) # => true or false
  #
  # @note This method is used internally to handle the authentication response
  # It will set the token and expiration time if successful
  #
  # @note This method is called internally after the authentication request
  def handle_auth_response(response)
    case response
    when Net::HTTPSuccess
      data = JSON.parse(response.body)
      @token = data["access_token"]
      
      # Calculate token expiration time (60 minutes from now)
      @token_expires_at = Time.now + 60 * 60
      
      @logger.info("Authentication successful. Token will expire at #{@token_expires_at}")
      true
    else
      @logger.error("Authentication failed: #{response.code} - #{response.message}")
      @logger.error("Response body: #{response.body}")
      false
    end
  end
  
  # Checks if the token is valid and refreshes if needed
  # @return [String] the valid token
  # @example
  #  client.ensure_valid_token # => "your_valid_token"
  #  @note This method is used to ensure that the token is valid before making API calls
  #  It will authenticate if the token is nil or expired
  #  It will return the valid token
  #  @note This method is called internally before making any API calls
  #
  def ensure_valid_token
    if @token.nil? || token_expired?
      @logger.info("Token is nil or expired. Authenticating...")
      authenticate
    end
    @token
  end
  
  # Check if the token is expired
  # Returns true if the token is expired or nil
  # Returns false if the token is still valid
  # Adds a buffer of 5 minutes to the expiration check
  # to ensure we don't use an expired token
  # @return [Boolean] true if the token is expired, false otherwise
  # @example
  #   client.token_expired? # => true or false
  #
  # @note This method is used internally to determine if the token needs to be refreshed
  def token_expired?
    return true if @token_expires_at.nil?
    
    # Add a buffer of 5 minutes to be safe
    buffer = 5 * 60
    Time.now > (@token_expires_at - buffer)
  end
  
 # Refactored make_api_call method to handle DELETE and other HTTP methods
 # @param endpoint [String] the API endpoint to call
 # @param method [Symbol] the HTTP method to use (default: :get)
 # @param payload [Hash] the payload to send with the request (default: nil)
 # @param hotel_id [String] the hotel ID to include in the request (default: nil)
 # @return [Hash] the response from the API call
 # @example
 #   client.make_api_call("/your_endpoint", :post, { key: "value" }, "hotel_id")
 #   client.make_api_call("/your_endpoint", :delete, nil, "hotel_id")
 #   client.make_api_call("/your_endpoint", :get)
 #   client.make_api_call("/your_endpoint", :put, { key: "value" }, "hotel_id")
 #   client.make_api_call("/your_endpoint", :patch, { key: "value" }, "hotel_id")
 # @note This method is used to make API calls to the OHIP system
  def make_api_call(endpoint, method = :get, payload = nil, hotel_id = nil)
    ensure_valid_token
    
    uri = URI.parse("#{@base_url}#{endpoint}")
    
    # Create the appropriate request based on the method
    request = case method.to_sym
              when :get
                Net::HTTP::Get.new(uri)
              when :post
                req = Net::HTTP::Post.new(uri)
                req.body = payload.to_json if payload
                req
              when :put
                req = Net::HTTP::Put.new(uri)
                req.body = payload.to_json if payload
                req
              when :delete
                Net::HTTP::Delete.new(uri)
              when :patch
                req = Net::HTTP::Patch.new(uri)
                req.body = payload.to_json if payload
                req
              else
                raise "Unsupported HTTP method: #{method}"
              end
    
    # Set common headers for all request types
    request["Authorization"] = "Bearer #{@token}"
    request["Accept"] = "application/json"
    request["Content-Type"] = "application/json" unless method.to_sym == :delete && payload.nil?
    request["x-app-key"] = @api_key
    
    # Add the hotel ID header if provided
    request["x-hotelid"] = hotel_id if hotel_id
    
    # Debug output
    if @logger.level == Logger::DEBUG 
      @logger.debug("Making API call to #{uri}")
      @logger.debug("Request method: #{method.upcase}")
      @logger.debug("Request headers:")
      request.each_header { |key, value| @logger.debug("  #{key}: #{value.gsub(/Bearer .*/, 'Bearer [REDACTED]')}") }
      @logger.debug("Request payload: #{payload.to_json}") if payload && method.to_sym != :get
    end
    
    response = send_request(uri, request)
    
    # Handle the response
    case response
    when Net::HTTPSuccess
      # For DELETE requests, the response might be empty
      if response.body && !response.body.empty?
        begin
          JSON.parse(response.body)
        rescue JSON::ParserError
          # If the response is not JSON, return a success indicator
          { "success" => true, "http_code" => response.code.to_i }
        end
      else
        # Empty response (common for DELETE)
        { "success" => true, "http_code" => response.code.to_i }
      end
    when Net::HTTPUnauthorized
      # Token might have expired
      @logger.info("Received 401 Unauthorized. Refreshing token and retrying...")
      authenticate
      make_api_call(endpoint, method, payload, hotel_id) # Retry the call
    else
      # Return error response details instead of nil
      error_details = nil
      begin
        if response.body && !response.body.empty?
          error_details = JSON.parse(response.body)
        end
      rescue JSON::ParserError => e
        @logger.error("Failed to parse error response: #{e.message}")
        error_details = { "raw_response" => response.body }
      end
      
      @logger.error("API call failed: #{response.code} - #{response.message}")
      if error_details
        @logger.error("Error details: #{error_details}")
      else
        @logger.error("No error details available")
      end
      
      # Return a hash with error information and the original response code
      {
        "error" => true,
        "http_code" => response.code.to_i,
        "http_message" => response.message,
        "details" => error_details
      }
    end
  end


end

# Example usage
# This is a standalone script to demonstrate the usage of the OHIPClient class
# It can be run directly to test the authentication and API call functionality
# You can replace the client_id, client_secret, api_key, username, and password with your actual values
# and run the script to see the output
# This script is for demonstration purposes only and should not be used in production
if __FILE__ == $0
  client_id = "client_id"
  client_secret = "client_secret"
  api_key = "api_key"
  username = "username" # Can be empty based on CURL command
  password = "password" # Can be empty based on CURL command
  
  client = OHIPClient.new(client_id, client_secret, api_key, username, password)
  
  # Authenticate
  if client.authenticate
    puts "Authentication successful!"
    puts "Token: #{client.token}"
    puts "Expires at: #{client.token_expires_at}"
    
    # Make an API call
    # result = client.make_api_call("/your_endpoint")
    # puts "API Result: #{result.inspect}"
  else
    puts "Authentication failed."
  end
end