#ifndef _REQUEST_H_
#define _REQUEST_H_

#include <string>
#include <cstring>
#include <map>
#include <sstream>
#include <iostream>

#include "crypto.h"
#include "Base64.h"
#include "config.h"

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
            request_stream << format_a_hander(it->first, it->second);
        }
        request_stream << "\r\n";
        if(!body.empty()) {
            request_stream << body;
        }
        return request_stream.str();
    }

    std::string format_a_hander(const std::string& key, const std::string &value) const {
        return std::string(key + ":" + value + "\r\n");
    }

    void set_method(const std::string& method) {
        this->method = method;
    }
    void set_method(std::string&& method) {
        this->method = std::move(method);
    }

    void set_path(const std::string& path) {
        this->path = path;
    }
    void set_path(std::string&& path) {
        this->path = std::move(path);
    }

    void set_protocol_version(const std::string& version) {
        this->protocol_version = version;
    }

    void set_protocol_version(std::string&& version) {
        this->protocol_version = std::move(version);
    }

    void add_header(const std::string &key, const std::string& value) {
        headers.emplace(key, value);
    }

    void add_header(std::string &&key, std::string &&value) {
        headers.emplace(std::move(key), std::move(value));
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

    void add_header_server_side_encryption(std::string key) {
        //server-side-encryption
        // std::string key = "xndhfjgloxnfhskxjdhfrixmdjfrdsid";
        std::string key64 = macaron::Base64::Encode(key);  //x-amz-server-side-encryption-customer-key
        // std::cout << key64 << std::endl;
        MD5 md5;
        unsigned char result[256];
        md5.Update(key.c_str(), key.size());
        int reslen = md5.Final(result);

        std::cout << reslen << std::endl;
        std::string key_md5 = macaron::Base64::Encode(std::string(reinterpret_cast<char*>(result), reslen));
        // std::cout << key_md5 << std::endl;      //x-amz-server-side-encryption-customer-key-md5

        add_header("x-amz-server-side-encryption-customer-key", key64);
        add_header("x-amz-server-side-encryption-customer-algorithm", "AES256");
        add_header("x-amz-server-side-encryption-customer-key-md5",key_md5);
    }
};

#endif // _REQUEST_H_