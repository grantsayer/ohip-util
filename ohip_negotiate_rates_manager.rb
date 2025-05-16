#!/usr/bin/env ruby

require 'yaml'
require 'optparse'
require 'logger'
require 'date'
require_relative 'ohip_client'

#
# This script manages negotiated rates for a hotel profile in the OHIP system.
# It allows you to fetch, display, and delete negotiated rates.
# It requires the OHIPClient class to interact with the OHIP API.
# 
class NegotiatedRatesManager
  attr_reader :logger, :client, :hotel_id, :profile_id, :environment

  def initialize
    @logger = Logger.new('logs/ohip_rates_manager.log')
    @logger.level = Logger::INFO
    @logger.formatter = proc do |severity, datetime, progname, msg|
      "#{datetime.strftime('%Y-%m-%d %H:%M:%S')} [#{severity}]: #{msg}\n"
    end
    
    parse_options
    load_config
    setup_client
  end

  def parse_options
    options = {}
    OptionParser.new do |opts|
      opts.banner = "Usage: negotiated_rates_manager.rb [options]"

      opts.on("-e", "--environment ENVIRONMENT", "Environment (uat or production)") do |env|
        options[:environment] = env
      end

      opts.on("-h", "--hotel-id HOTEL_ID", "Hotel ID") do |hotel_id|
        options[:hotel_id] = hotel_id
      end

      opts.on("-p", "--profile-id PROFILE_ID", "Profile ID") do |profile_id|
        options[:profile_id] = profile_id
      end

      opts.on("--help", "Show this help message") do
        puts opts
        exit
      end
    end.parse!

    # Validate required options
    unless options[:environment] && ["uat", "production"].include?(options[:environment].downcase)
      puts "Error: Environment must be specified as either 'uat' or 'production'"
      exit 1
    end

    unless options[:hotel_id]
      puts "Error: Hotel ID must be specified"
      exit 1
    end

    unless options[:profile_id]
      puts "Error: Profile ID must be specified"
      exit 1
    end

    @environment = options[:environment].downcase
    @hotel_id = options[:hotel_id]
    @profile_id = options[:profile_id]
  end

  def load_config
    begin
      @config = YAML.load_file('config.yml')
      unless @config.key?(@environment)
        puts "Error: Environment '#{@environment}' not found in config.yml"
        exit 1
      end
    rescue => e
      puts "Error loading config file: #{e.message}"
      exit 1
    end
  end

  def setup_client
    env_config = @config[@environment]
    @client = OHIPClient.new(
      env_config['client_id'],
      env_config['client_secret'],
      env_config['api_key'],
      env_config['username'],
      env_config['password']
    )
    
    # Override base_url if specified in config
    @client.instance_variable_set('@base_url', env_config['base_url']) if env_config['base_url']
    
    # Authenticate
    unless @client.authenticate
      logger.error("Authentication failed for environment #{@environment}")
      puts "Authentication failed for environment #{@environment}"
      exit 1
    end
    
    logger.info("Successfully authenticated to OHIP API in #{@environment} environment")
    puts "Successfully authenticated to OHIP API in #{@environment} environment"
  end

  def get_negotiated_rates
    logger.info("Fetching negotiated rates for profile #{@profile_id}")
    puts "Fetching negotiated rates for profile #{@profile_id}"
    
    endpoint = "/rtp/v1/profiles/#{@profile_id}/negotiatedRates"
    response = @client.make_api_call(endpoint, :get, nil, @hotel_id)
    
    if response.is_a?(Hash) && response["error"]
      logger.error("Failed to fetch negotiated rates: #{response}")
      puts "Failed to fetch negotiated rates: #{response["http_message"]}"
      return []
    end
    
    # Check if negotiations key exists
    if !response.is_a?(Hash) || !response["negotiatedRates"].is_a?(Array)
      logger.warn("No negotiations found or unexpected response format")
      puts "No negotiations found or unexpected response format"
      return []
    end
    
    rates = response["negotiatedRates"]
    logger.info("Found #{rates.size} negotiated rates")
    puts "Found #{rates.size} negotiated rates"
    
    rates
  end

  def display_rates(rates)
    return if rates.empty?
    
    puts "\nNegotiated Rates Found:"
    puts "=" * 80
    
    rates.each_with_index do |rate, index|
      rate_code = rate["ratePlanCode"] || "N/A"
      hotel_id = rate["hotelId"] || "N/A"
      
      # Handle negotiated profile information if present
      if rate["negotiatedProfile"] && !rate["negotiatedProfile"].empty?
        profile_info = rate["negotiatedProfile"][0]
        
        # Extract profile IDs
        profile_ids = []
        if profile_info["profileIdList"]
          profile_info["profileIdList"].each do |profile_id_item|
            profile_ids << "#{profile_id_item['id']} (#{profile_id_item['type']})"
          end
        end
        
        # Extract profile name information
        profile_name = "N/A"
        profile_full_name = "N/A"
        if profile_info["profileName"]
          profile_name = profile_info["profileName"]["name"] || "N/A"
          profile_full_name = profile_info["profileName"]["fullName"] || "N/A"
        end
        
        # Extract rate information
        rate_info = "N/A"
        start_date = "N/A"
        inactive = "N/A"
        negotiated_rate_order = "N/A"
        
        if profile_info["rateInfoList"] && !profile_info["rateInfoList"].empty?
          rate_info_item = profile_info["rateInfoList"][0]
          start_date = rate_info_item["start"] || "N/A"
          inactive = rate_info_item["inactive"].to_s || "N/A"
          negotiated_rate_order = rate_info_item["negotiatedRateOrder"].to_s || "N/A"
        end
        
        profile_type = profile_info["profileType"] || "N/A"
        
        # Display the rate information
        puts "#{index + 1}. Rate Plan Code: #{rate_code}"
        puts "   Hotel ID: #{hotel_id}"
        puts "   Profile Type: #{profile_type}"
        puts "   Profile Name: #{profile_name}"
        puts "   Full Name: #{profile_full_name}"
        puts "   Profile IDs:"
        
        if profile_ids.empty?
          puts "     None found"
        else
          profile_ids.each do |pid|
            puts "     #{pid}"
          end
        end
        
        puts "   Start Date: #{start_date}"
        puts "   Inactive: #{inactive}"
        puts "   Negotiated Rate Order: #{negotiated_rate_order}"
      else
        # Fallback for rates without negotiated profile information
        puts "#{index + 1}. Rate Plan Code: #{rate_code}"
        puts "   Hotel ID: #{hotel_id}"
        puts "   No detailed profile information available"
        
        # Still try to extract any other available fields for display
        start_date = rate["effectiveDate"] || "N/A"
        end_date = rate["expirationDate"] || "N/A"
        rate_id = rate["ratePlanId"] || "N/A"
        
        puts "   Rate Plan ID: #{rate_id}"
        puts "   Effective Date: #{start_date}"
        puts "   Expiration Date: #{end_date}"
      end
      
      puts "-" * 80
    end
  end

  def delete_negotiated_rates(rates)
    return 0 if rates.empty?
    
    success_count = 0
    failure_count = 0
    
    puts "\nDeleting negotiated rates..."
    
    rates.each_with_index do |rate, index|
      rate_code = rate["ratePlanCode"] || "N/A"
      
      # Extract the start date from the new structure
      start_date = nil
      
      if rate["negotiatedProfile"] && !rate["negotiatedProfile"].empty?
        profile_info = rate["negotiatedProfile"][0]
        if profile_info["rateInfoList"] && !profile_info["rateInfoList"].empty?
          start_date = profile_info["rateInfoList"][0]["start"]
        end
      end
      
      # Fallback to old structure if needed
      start_date ||= rate["effectiveDate"]
      
      # Extract rate plan ID - this might need adjustment based on API requirements
      # Assuming the rate plan code is used as the ID for deletion
      rate_id = rate["ratePlanId"] || rate["ratePlanCode"]
      
      # Skip if missing required data
      unless rate_id && start_date
        logger.warn("Skipping rate #{index + 1}: Missing rate plan ID or start date")
        puts "Skipping rate #{index + 1}: Missing rate plan ID or start date"
        failure_count += 1
        next
      end
      
      # Format date correctly - API expects YYYY-MM-DD
      begin
        # Check if date is already in correct format
        if start_date =~ /^\d{4}-\d{2}-\d{2}$/
          formatted_date = start_date
        else
          formatted_date = Date.parse(start_date).strftime('%Y-%m-%d')
        end
      rescue => e
        logger.warn("Skipping rate #{index + 1}: Unable to parse date #{start_date} - #{e.message}")
        puts "Skipping rate #{index + 1}: Unable to parse date #{start_date}"
        failure_count += 1
        next
      end
      
      endpoint = "/rtp/v1/hotels/#{@hotel_id}/profiles/#{@profile_id}/startDate/#{formatted_date}/negotiatedRates/#{rate_id}"
      logger.info("Deleting rate plan #{rate_id} (#{rate_code}) with endpoint: #{endpoint}")
      puts "Deleting rate plan: #{rate_code} (ID: #{rate_id}) (#{index + 1}/#{rates.size})"
      
      response = @client.make_api_call(endpoint, :delete, nil, @hotel_id)
      
      if response.is_a?(Hash) && response["error"]
        logger.error("Failed to delete rate plan #{rate_id}: #{response}")
        puts "  Failed: #{response["http_message"] || response["details"] || "Unknown error"}"
        failure_count += 1
      else
        logger.info("Successfully deleted rate plan #{rate_id}")
        puts "  Success!"
        success_count += 1
      end
    end
    
    puts "\nDeletion Summary:"
    puts "Total rates: #{rates.size}"
    puts "Successfully deleted: #{success_count}"
    puts "Failed: #{failure_count}"
    
    success_count
  end

  def run
    puts "\n=== OHIP Negotiated Rates Manager ==="
    puts "Environment: #{@environment}"
    puts "Hotel ID: #{@hotel_id}"
    puts "Profile ID: #{@profile_id}"
    puts "=" * 40
    
    # Step 1: Get all negotiated rates for the profile
    rates = get_negotiated_rates
    
    # Step 2: Display the rates found
    display_rates(rates)
    
    # Step 3: Confirm deletion
    if !rates.empty?
      print "\nDo you want to proceed with deleting these rates? (y/n): "
      response = gets.chomp.downcase
      
      if response == 'y'
        # Step 4: Delete the rates
        deleted_count = delete_negotiated_rates(rates)
        
        logger.info("Operation completed. Deleted #{deleted_count} of #{rates.size} negotiated rates")
        puts "\nOperation completed. See log file for details."
      else
        logger.info("User cancelled the deletion operation")
        puts "\nDeletion cancelled."
      end
    end
  end
end

# Run the application
if __FILE__ == $0
  app = NegotiatedRatesManager.new
  app.run
end
