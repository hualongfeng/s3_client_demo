#include <string>
#include <sstream>

#include "Base64.h"
#include "crypto.h"
#include "request.h"


std::string get_signature_key(std::string_view key,
                              std::string_view dateStamp,
                              std::string_view regionName = "default",
                              std::string_view serviceName = "s3") {

    // std::cout << "key: " << key << std::endl;
    // std::cout << "dateStamp: " << dateStamp << std::endl;
    // std::cout << "regionName: " << regionName << std::endl;
    // std::cout << "serviceName: " << serviceName << std::endl;

    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int reslen = 0;
    HMAC_SHA256 hmac_sha256(std::string("AWS4"+std::string(key)).c_str(), key.size()+4);
    hmac_sha256.Update(dateStamp.data(), dateStamp.size());
    reslen = hmac_sha256.Final(result);

    hmac_sha256.Reset(result, reslen);
    hmac_sha256.Update(regionName.data(), regionName.size());
    reslen = hmac_sha256.Final(result);

    hmac_sha256.Reset(result, reslen);
    hmac_sha256.Update(serviceName.data(), serviceName.size());
    reslen = hmac_sha256.Final(result);

    hmac_sha256.Reset(result, reslen);
    hmac_sha256.Update("aws4_request", 12);
    reslen = hmac_sha256.Final(result);

    return std::string(reinterpret_cast<char*>(result), reslen);
};

/*
  return: 20201228/default/s3/aws4_request
*/
std::string credential_scope(std::string_view dateStamp,
                             std::string_view regionName = "default",
                             std::string_view serviceName = "s3"){
    std::stringstream ss;
    ss << dateStamp << "/" << regionName << "/" << serviceName << "/" << "aws4_request";
    return ss.str();
}


std::string string_to_sign_v4(std::string_view amzDate,
                              std::string_view credential_scope,
                              std::string_view hashValSha256) {
    std::string algorithm = "AWS4-HMAC-SHA256";
    std::stringstream ss;
    ss << algorithm << "\n"
       << amzDate << "\n"
       << credential_scope << "\n"
       << hashValSha256;
    return ss.str();

}

/*
     example:
     string to sign: "AWS4-HMAC-SHA256\n"
                     "20201228T104452Z\n"
                     "20201228/default/s3/aws4_request\n"
                     "d274d57b0bd246b6e6335d047573d209890c2422828e9cec2b93b9a1a54eeb41"
*/
std::string get_v4_signature(std::string_view signKey,
                             std::string_view stringToSign){
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int reslen = 0;

    static constexpr size_t BUF_SIZE = 64;

    HMAC_SHA256 hmac_sha256(signKey.data(), signKey.size());
    hmac_sha256.Update(stringToSign.data(), stringToSign.size());
    reslen = hmac_sha256.Final(result);

    char buffer[BUF_SIZE+1];
    for(int i = 0; i < reslen; i++) {
        snprintf(buffer+2*i, 3, "%02x", result[i]);
    }
    return std::string(buffer, BUF_SIZE);
}



std::string authorization_header(httpRequest& httpRequest) {

    auto& http_verb = httpRequest.method;
    auto& canonical_uri = httpRequest.path;
    std::string canonical_query_string = "";
    int headers_len = 0;
    int headers_valuelen = 0;
    auto& headers = httpRequest.headers;
    for(auto it = headers.begin(); it != headers.end(); it++){
        headers_len += it->first.size();
        headers_valuelen += it->second.size();
    }
    std::string canonical_headers;
    std::string signed_headers;
    canonical_headers.reserve(headers_len + headers_valuelen + headers.size()*2);
    signed_headers.reserve(headers_len + headers.size());
    for(auto it = headers.cbegin(); it != headers.cend(); it++){
        canonical_headers += it->first;
        canonical_headers += ":";
        canonical_headers += it->second;
        canonical_headers += "\n";

        signed_headers += it->first;
        signed_headers += ";";
    }
    signed_headers.resize(signed_headers.size() - 1); //drop last ';';

    auto& content_sha256 = headers["x-amz-content-sha256"];

    std::string canonical_request;
    canonical_request.reserve(5 + http_verb.size() + canonical_uri.size() + canonical_query_string.size()+ canonical_headers.size() + signed_headers.size() + content_sha256.size());
    canonical_request += http_verb;
    canonical_request += "\n";
    canonical_request += canonical_uri;
    canonical_request += "\n";
    canonical_request += canonical_query_string;
    canonical_request += "\n";
    canonical_request += canonical_headers;
    canonical_request += "\n";
    canonical_request += signed_headers;
    canonical_request += "\n";
    canonical_request += content_sha256;

    std::cout << "canonical_request:\n " << canonical_request << std::endl;

    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int reslen = 0;
    SHA256 sha256;
    sha256.Update(canonical_request.c_str(), canonical_request.size());
    reslen = sha256.Final(result);
    char buffer[EVP_MAX_MD_SIZE*2+1];
    for(int i = 0; i < reslen; i++) {
        snprintf(buffer+2*i, 3, "%02x", result[i]);
    }
    std::string hashValSha256(buffer);

    
    std::string algorithm = "AWS4-HMAC-SHA256";
    std::string amzDate = s3Time::get_v4();
    std::string dateStamp = amzDate.substr(0,8);
    std::string sign_key = get_signature_key(secret_key, dateStamp);
    std::string credentialScope = credential_scope(dateStamp);
    std::string stringToSign = string_to_sign_v4(amzDate, credentialScope, hashValSha256);
    // std::cout << "string_to_sign:\n" << stringToSign << std::endl;
    std::stringstream ss;
    ss << algorithm << " " << "Credential=" << access_key
       << "/" <<  credentialScope
       << ", " << "SignedHeaders=" << signed_headers
       << ", " << "Signature=" << get_v4_signature(sign_key, stringToSign);

    return ss.str();
}