
require 'time'
require 'openssl'
require 'base64'

module S3FileLib
  BLOCKSIZE_TO_READ = 1024 * 1000 unless const_defined?(:BLOCKSIZE_TO_READ)
  AMZSHA256 = Digest::SHA256.hexdigest ""
  
  def self.build_headers(date, authorization)

    headers = {
      'x-amz-content-sha256' => AMZSHA256,
      'x-amz-date' => date,
      'Authorization' => authorization
    }

    return headers
  end
  
  def self.get_md5_from_s3(bucket,path,aws_access_key_id,aws_secret_access_key,region)
    return get_digests_from_s3(bucket,path,aws_access_key_id,aws_secret_access_key,region)["md5"]
  end
  
  def self.get_digests_from_s3(bucket,path,aws_access_key_id,aws_secret_access_key,region)
    client = self.client
    now, auth_string = get_s3_auth("HEAD", bucket,path,aws_access_key_id,aws_secret_access_key, region)
    
    headers = build_headers(now, auth_string)
    endpoint = build_endpoint(region)
    headers['host'] = "%s.%s" % [bucket,endpoint]

    url = "https://#{bucket}.#{endpoint}"

    response = client.head("#{url}#{path}", headers)
    
    etag = response.headers[:etag].gsub('"','')
    digest = response.headers[:x_amz_meta_digest]
    digests = digest.nil? ? {} : Hash[digest.split(",").map {|a| a.split("=")}]

    return {"md5" => etag}.merge(digests)
  end

  def self.get_from_s3(bucket,path,aws_access_key_id,aws_secret_access_key,region)
    client = self.client
    now, auth_string = get_s3_auth("GET", bucket,path,aws_access_key_id,aws_secret_access_key, region)
    endpoint = build_endpoint(region)
    url = "https://#{bucket}.#{endpoint}"    

    headers = build_headers(now, auth_string)
    headers['host'] = "%s.%s" % [bucket,endpoint]
    retries = 5
    for attempts in 0..5
      begin
        response = client::Request.execute(:method => :get, :url => "#{url}#{path}", :raw_response => true, :headers => headers)
        break
      rescue => e
        if attempts < retries
          Chef::Log.warn e.response
          next
        else
          Chef::Log.fatal e.response
          raise e
        end
      end
    end

    return response
  end

  def self.get_s3_auth(method, bucket,path,aws_access_key_id,aws_secret_access_key, region)
    service = 's3'
    endpoint = build_endpoint(region)
    host = "%s.%s" % [bucket,endpoint]
    now = Time.now().utc.strftime('%Y%m%dT%H%M%SZ')
    datestamp = Time.now().utc.strftime('%Y%m%d')
    payload_hash = amzsha256 = AMZSHA256
    canonical_headers = 'host:' + host + "\n" + 'x-amz-content-sha256:' + amzsha256 + "\n" + 'x-amz-date:' + now + "\n"
    signed_headers = 'host;x-amz-content-sha256;x-amz-date'
    canonical_request = "#{method}\n%s\n\n%s\n%s\n%s" % [path,canonical_headers,signed_headers,payload_hash]
    canonical_request_sha256 = Digest::SHA256.hexdigest canonical_request
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = "%s/%s/%s/aws4_request" % [datestamp,region,service]
    string_to_sign = "%s\n%s\n%s\n%s" % [algorithm,now,credential_scope,canonical_request_sha256]
    signing_key = getSignatureKey(aws_secret_access_key, datestamp, region, service)
    signature = OpenSSL::HMAC.hexdigest('sha256', signing_key, string_to_sign)
    auth_string = algorithm + ' ' + 'Credential=' + aws_access_key_id + '/' + credential_scope + ',' +  'SignedHeaders=' + signed_headers + ',' + 'Signature=' + signature
        
    [now,auth_string]
  end

  def self.aes256_decrypt(key, file)
    Chef::Log.debug("Decrypting S3 file.")
    key = key.strip
    require "digest"
    key = Digest::SHA256.digest(key) if(key.kind_of?(String) && 32 != key.bytesize)
    aes = OpenSSL::Cipher.new('AES-256-CBC')
    aes.decrypt
    aes.key = key
    decrypt_file = Tempfile.new("chef-s3-decrypt")
    File.open(decrypt_file, "wb") do |df|
      File.open(file, "rb") do |fi|
        while buffer = fi.read(BLOCKSIZE_TO_READ)
          df.write aes.update(buffer)
        end
      end
      df.write aes.final
    end
    decrypt_file
  end

  def self.verify_sha256_checksum(checksum, file)
    recipe_sha256 = checksum
    local_sha256 = Digest::SHA256.new

    File.open(file, "rb") do |fi|
      while buffer = fi.read(BLOCKSIZE_TO_READ)
        local_sha256.update buffer
      end
    end

    Chef::Log.debug "sha256 provided #{recipe_sha256}"
    Chef::Log.debug "sha256 of local object is #{local_sha256.hexdigest}"

    local_sha256.hexdigest == recipe_sha256
  end

  def self.verify_md5_checksum(checksum, file)
    s3_md5 = checksum
    local_md5 = Digest::MD5.new

    # buffer the checksum which should save RAM consumption
    File.open(file, "rb") do |fi|
      while buffer = fi.read(BLOCKSIZE_TO_READ)
        local_md5.update buffer
      end
    end

    Chef::Log.debug "md5 of remote object is #{s3_md5}"
    Chef::Log.debug "md5 of local object is #{local_md5.hexdigest}"

    local_md5.hexdigest == s3_md5
  end

  def self.client
    require 'rest-client'
    RestClient.proxy = ENV['http_proxy']
    RestClient
  end

  def self.getSignatureKey(key, dateStamp, regionName, serviceName)
      kDate    = OpenSSL::HMAC.digest('sha256', "AWS4" + key, dateStamp)
      kRegion  = OpenSSL::HMAC.digest('sha256', kDate, regionName)
      kService = OpenSSL::HMAC.digest('sha256', kRegion, serviceName)
      kSigning = OpenSSL::HMAC.digest('sha256', kService, "aws4_request")

      kSigning
  end
  def self.build_endpoint(region)
      endpointlist = {
          "ap-northeast-1" => "s3-ap-northeast-1.amazonaws.com",
          "ap-southeast-1" => "s3-ap-southeast-1.amazonaws.com",
          "ap-southeast-2" => "s3-ap-southeast-2.amazonaws.com",
          "cn-north-1" => "s3.cn-north-1.amazonaws.com.cn",
          "eu-west-1" => "s3-eu-west-1.amazonaws.com",
          "sa-east-1" => "s3-sa-east-1.amazonaws.com",
          "us-east-1" => "s3.amazonaws.com",
          "us-gov-west-1" => "s3-us-gov-west-1.amazonaws.com",
          "us-west-1" => "s3-us-west-1.amazonaws.com",
          "us-west-2" => "s3-us-west-2.amazonaws.com",
          "eu-central-1" => "s3.eu-central-1.amazonaws.com"
      }
    return endpointlist[region]
  end

end
