#include "crypto.h"
#include "Base64.h"
#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <string>
#include <cstring>
#include <istream>
#include <ostream>
#include <map>
#include <list>
#include <boost/algorithm/string/case_conv.hpp>

using boost::asio::ip::tcp;

const char* access_key = "0555b35654ad1656d804";
const char* secret_key = "h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==";

std::string localtime() {
   time_t rawtime;
   struct tm *info;
   char buffer[32];
   time( &rawtime );
   info = gmtime( &rawtime );
   //strftime(buffer, 80, "%a, %d %b %Y %H:%M:%S +0000", info);
   strftime(buffer, 80, "%a, %d %b %Y %H:%M:%S %Z", info);
//    strftime(buffer, 80, "%Y%m%dT%H%M%SZ", info);
   return std::string(buffer);
}

class s3Time {
public:
    static std::string get_v2() {
        time_t rawtime;
        time(&rawtime);
        auto utc_time = gmtime(&rawtime);
        char buffer[32];
        //strftime(buffer, 80, "%a, %d %b %Y %H:%M:%S +0000", info);
        strftime(buffer, 32, "%a, %d %b %Y %H:%M:%S %Z", utc_time);
        return std::string(buffer);
    }

    static std::string get_v4() {
        time_t rawtime;
        time(&rawtime);
        auto utc_time = gmtime(&rawtime);
        char buffer[32];
        strftime(buffer, 80, "%Y%m%dT%H%M%SZ", utc_time);
        return std::string(buffer);
    }
};

class httpRequest {
public:
    std::string method;
    std::string path;
    std::string protocol_version;
    std::map<std::string, std::string> headers;
    std::string body;

    const std::string get_request() const {
        std::stringstream request_stream;
        request_stream << method << " " << path << " " << protocol_version << "\r\n";
        for(auto it = headers.cbegin(); it != headers.cend(); it++) {
            request_stream << get_a_hander(it->first, it->second);
        }
        request_stream << "\r\n";
        if(!body.empty()) {
            request_stream << body;
        }
        return request_stream.str();
    }

    std::string get_a_hander(const std::string& key, const std::string &value) const {
        return std::string(key + ":" + value + "\r\n");
    }

    std::string auth_v2() {
        std::stringstream ss;
        ss  << method + "\n";
        // auto md5_it = headers.find("Content-MD5");
        // if(md5_it != headers.end()) {
        //     ss << md5_it->second << "\n";
        // }else {
        //     ss << "\n";
        // }
        ss << "\n";

        // auto type_it = headers.find("Content-Type");
        // if(type_it != headers.end()) {
        //     ss << type_it->second << "\n";
        // }else {
        //     ss << "\n";
        // }
        ss << "\n";

        //date
        ss << "\n";

        //AmzHeaders
        for(auto it = headers.cbegin(); it != headers.cend(); it++) {
            if(it->first[0] == 'x') {
                ss << it->first << ":" << it->second << "\n";
            }
        }

        //Resource
        ss << path;

        //compute sign
        const auto signature = ss.str();
        std::cout << "string_to_sign: \n" << signature << std::endl;
        HMAC_SHA1 hmac_sha1(secret_key, strlen(secret_key));
        hmac_sha1.Update(signature.c_str(), signature.size());
        char result[32];
        int reslen = hmac_sha1.Final(result);
        std::string ret = macaron::Base64::Encode(std::string(result, reslen));
        std::cout << "Signature: " << ret << std::endl;
        return ret;
    }
};

class getRequest {
public:
    httpRequest request;

    void set_value(std::string &time) {
        request.method = "GET";
        request.path   = "/testbkt/object";
        request.protocol_version = "HTTP/1.1";
        request.headers.emplace("Host", "10.239.241.160:8000");
        request.headers.emplace("Accept-Encoding", "identity");
        request.headers.emplace("Content-Length", "0");
        // request.headers.emplace("Range", "bytes=0-103");
        request.headers.emplace(std::string("x-amz-date"), time);
        request.headers.emplace("x-amz-server-side-encryption-customer-key", "eG5kaGZqZ2xveG5maHNreGpkaGZyaXhtZGpmcmRzaWQ=");
        request.headers.emplace("x-amz-server-side-encryption-customer-algorithm", "AES256");
        request.headers.emplace("x-amz-server-side-encryption-customer-key-md5","B64HxGtDGAjCk350zDHClQ==");
        std::string sign = request.auth_v2();
        request.headers.emplace(std::string("Authorization"), std::string("AWS 0555b35654ad1656d804:"+sign));
    }

    std::string get_value() {
        return request.get_request();
    }
};


class deleteRequest {
public:
    httpRequest request;

    void set_value(std::string &time) {
        request.method = "DELETE";
        request.path   = "/testbkt";
        request.protocol_version = "HTTP/1.1";
        request.headers.emplace("Host", "10.239.241.160:8000");
        request.headers.emplace("Accept-Encoding", "identity");
        request.headers.emplace("Content-Length", "0");
        request.headers.emplace(std::string("x-amz-date"), time);
        std::string sign = request.auth_v2();
        request.headers.emplace(std::string("Authorization"), std::string("AWS 0555b35654ad1656d804:"+sign));
    }

    std::string get_value() {
        return request.get_request();
    }
};


class putObjectRequest {
public:
    httpRequest request;

    void set_value(std::string &time) {
        request.method = "PUT";
        request.path   = "/testbkt/object";
        request.protocol_version = "HTTP/1.1";
        request.headers.emplace("Host", "10.239.241.160:8000");
        request.headers.emplace("Accept-Encoding", "identity");
        request.headers.emplace("Content-Length", "103");
        request.headers.emplace(std::string("x-amz-date"), time);
        // request.headers.emplace("x-amz-server-side-encryption-customer-key", "eG5kaGZqZ2xveG5maHNreGpkaGZyaXhtZGpmcmRzaWQ=");
        // request.headers.emplace("x-amz-server-side-encryption-customer-algorithm", "AES256");
        // request.headers.emplace("x-amz-server-side-encryption-customer-key-md5","B64HxGtDGAjCk350zDHClQ==");
        std::string sign = request.auth_v2();
        request.headers.emplace(std::string("Authorization"), std::string("AWS 0555b35654ad1656d804:"+sign));
        request.body = "<CreateBucketConfiguration><LocationConstraint>default</LocationConstraint></CreateBucketConfiguration>";
    }

    std::string get_value() {
        return request.get_request();
    }

};


class putRequest {
public:
    httpRequest request;

    void set_value(std::string &time) {
        request.method = "PUT";
        request.path   = "/testbkt/";
        request.protocol_version = "HTTP/1.1";
        request.headers.emplace("Host", "10.239.241.160:8000");
        request.headers.emplace("Accept-Encoding", "identity");
        request.headers.emplace("Content-Length", "103");
        request.headers.emplace(std::string("x-amz-date"), time);
        std::string sign = request.auth_v2();
        request.headers.emplace(std::string("Authorization"), std::string("AWS 0555b35654ad1656d804:"+sign));
        request.body = "<CreateBucketConfiguration><LocationConstraint>default</LocationConstraint></CreateBucketConfiguration>";
    }

    std::string get_value() {
        return request.get_request();
    }

};


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
    std::map<std::string, std::string> headers;
    for(auto it = httpRequest.headers.begin(); it != httpRequest.headers.end(); it++){

        headers_len += it->first.size();
        headers_valuelen += it->second.size();
        std::string key = it->first;
        boost::algorithm::to_lower(key);
        headers.emplace(std::move(key), it->second);
    }
//    for(auto it = headers.begin(); it != headers.end(); it++){
//         headers_len += it->first.size();
//         headers_valuelen += it->second.size();
//         boost::algorithm::to_lower(it->first);
//     }
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

class getRequestV4 {
public:
    httpRequest request;

    void set_value(std::string &time) {
        request.method = "GET";
        request.path   = "/mycontainers1/";
        request.protocol_version = "HTTP/1.1";
        request.headers.emplace("Host", "10.239.241.160:8000");
        request.headers.emplace("Accept-Encoding", "identity");
        request.headers.emplace("Content-Length", "0");
        // request.headers.emplace("Range", "bytes=0-103");
        request.headers.emplace(std::string("x-amz-date"), time);
        request.headers.emplace("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        std::string sign = authorization_header(request);
        request.headers.emplace(std::string("Authorization"), sign);
    }

    std::string get_value() {
        return request.get_request();
    }
};




//https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
int main(int argc, char* argv[]) {

//     std::string canonical_request = "";



//     std::string signature = "AWS4-HMAC-SHA256\n"
//     "20201228T104452Z\n"
//     "20201228/default/s3/aws4_request\n"
//     "d274d57b0bd246b6e6335d047573d209890c2422828e9cec2b93b9a1a54eeb41";

//     std::string sign_key = get_signature_key(secret_key, "20201228");
//     for(int i = 0; i < sign_key.size(); i++) {
//         printf("%02x", reinterpret_cast<const unsigned char*>(sign_key.c_str())[i]);
//     }
//     printf("\n");



//     unsigned char result[256];
//     HMAC_SHA256 hmac_sha256(std::string("AWS4"+std::string(secret_key)).c_str(), strlen(secret_key)+4);
//     hmac_sha256.Update("20201228", 8);
//     unsigned int reslen = hmac_sha256.Final(result);
//     hmac_sha256.Reset(result, reslen);
//     hmac_sha256.Update("default", 7);
//     reslen = hmac_sha256.Final(result);
//     hmac_sha256.Reset(result, reslen);
//     hmac_sha256.Update("s3", 2);
//     reslen = hmac_sha256.Final(result);
//     hmac_sha256.Reset(result, reslen);
//     hmac_sha256.Update("aws4_request", 12);
//     reslen = hmac_sha256.Final(result);

//     for(int i = 0; i < reslen; i++) {
//         printf("%02x", reinterpret_cast<unsigned char*>(result)[i]);
//     }
//     printf("\n");

//     std::cout << get_v4_signature(std::string(reinterpret_cast<char*>(result), reslen), signature) << std::endl;

//     hmac_sha256.Reset(result, reslen);
//     hmac_sha256.Update(signature.c_str(), signature.size());
//     reslen = hmac_sha256.Final(result);

//     for(int i = 0; i < reslen; i++) {
//         printf("%02x", reinterpret_cast<unsigned char*>(result)[i]);
//     }
//     printf("\n");

//     std::string http_verb = "GET";
//     std::string canonical_uri = "/mycontainers1/";
//     std::string canonical_query_string = "delimiter=%2F";
//     std::vector<std::string> headers = {"host", "x-amz-date", "x-amz-content-sha256"};
//     std::sort(headers.begin(), headers.end());
//     std::string canonical_headers =
//     "host:10.239.241.160:8000\n"
//     "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
//     "x-amz-date:20201228T104452Z\n";
//     std::string signed_headers = headers[0]+";"+headers[1]+";"+headers[2];
//     std::stringstream ss1;
//     ss1 << http_verb << "\n"
//        << canonical_uri << "\n"
//        << canonical_query_string << "\n"
//        << canonical_headers << "\n"
//        << signed_headers << "\n"
//        << "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

//     canonical_request = ss1.str();
//     std::cout << canonical_request << std::endl;

//     // "GET /mycontainers1/?delimiter=%2F HTTP/1.1\r\n"
//     // "Host: 10.239.241.160:8000\r\n"
//     // "Accept-Encoding: identity\r\n"
//     // "Content-Length: 0\r\n"
//     // "x-amz-date: 20201228T104452Z";
//     //"Authorization: AWS4-HMAC-SHA256 Credential=0555b35654ad1656d804/20201228/default/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=cf38f0829fad8c599c68817c5c639d435101ac278cf71dd25ff6495ddad040f3"; 
//     SHA256 sha256;
//     sha256.Update(canonical_request.c_str(), canonical_request.size());
//     reslen = sha256.Final(result);
//     for(int i = 0; i < reslen; i++) {
//         printf("%02x", reinterpret_cast<unsigned char*>(result)[i]);
//     }
//     printf("\n");


// std::cout << "--------------------------------" << std::endl;

// //server-side-encryption
//     std::string key = "xndhfjgloxnfhskxjdhfrixmdjfrdsid";
//     std::string ret = macaron::Base64::Encode(key);  //x-amz-server-side-encryption-customer-key
//     std::cout << ret << std::endl;
//     MD5 md5;
//     md5.Update(key.c_str(), key.size());
//     reslen = md5.Final(result);

//     std::cout << reslen << std::endl;
//     ret = macaron::Base64::Encode(std::string(reinterpret_cast<char*>(result), reslen));
//     std::cout << ret << std::endl;      //x-amz-server-side-encryption-customer-key-md5



// return 0;

    std::string host = "www.baidu.com";

    boost::asio::io_context io_context;
    try{
        tcp::resolver resolver{io_context};
        tcp::socket socket(io_context);
        boost::system::error_code ec;
        // auto endpoints = resolver.resolve(host, "http", ec);
        auto endpoints = resolver.resolve("10.239.241.160", "8000", ec);
        for(auto&& endpoint : endpoints) {
            std::cout << endpoint.service_name() << " "
                      << endpoint.host_name() << " "
                      << endpoint.endpoint()
                      << std::endl;
        }
        if(ec) {
            std::cout << "Error code: " << ec << std::endl;
            return 1;
        }
        const auto connected_endpoint = boost::asio::connect(socket, endpoints);
        std::cout << connected_endpoint << std::endl;


        std::string time = localtime();
        time = s3Time::get_v4();
        std::cout << "time: " << time << std::endl;


        // getRequest req;
        getRequestV4 req;
        req.set_value(time);
        // deleteRequest req;
        // putRequest req;
        // putObjectRequest req;
        // req.set_value(time);
        const auto request = req.get_value();

        std::cout << request << std::endl;

        boost::asio::write(socket, boost::asio::buffer(request), ec);

        // method 1 to read
        std::cout << "-----------------------------------------------------" << std::endl;
        for (;;) {
            boost::array<char, 128> buf;
            boost::system::error_code ec;
            size_t len = socket.read_some(boost::asio::buffer(buf), ec);
            if (ec == boost::asio::error::eof) {
                std::cout << "read EOF" << std::endl;
                break; //Connection closed cleanly by peer.
            } else if (ec) {
                throw boost::system::system_error(ec);
            }

            std::cout.write(buf.data(), len);
            std::cout << std::flush;
        }

        // //method 2 to read
        // std::string response;
        // //boost::asio::connect(socket, endpoints);
        // boost::asio::write(socket, boost::asio::buffer(request), ec);
        // boost::asio::read(socket, boost::asio::dynamic_buffer(response), ec);
        // if(ec && ec.value() != 2) throw boost::system::system_error(ec);
        // std::cout << response << std::endl;


    }catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
