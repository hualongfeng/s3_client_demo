#include "s3_hmac.h"
#include "Base64.h"
#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <string>
#include <istream>
#include <ostream>
#include <map>

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
   return std::string(buffer);
}

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
            request_stream << body << "\r\n";
        }
        return request_stream.str();
    }

    std::string get_a_hander(const std::string& key, const std::string &value) const {
        return std::string(key + ":" + value + "\r\n");
    }

    std::string auth() {
        std::stringstream ss;
        ss  << method + "\n";
        auto md5_it = headers.find("Content-MD5");
        if(md5_it != headers.end()) {
            ss << md5_it->second << "\n";
        }else {
            ss << "\n";
        }

        auto type_it = headers.find("Content-Type");
        if(type_it != headers.end()) {
            ss << type_it->second << "\n";
        }else {
            ss << "\n";
        }

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
        return ret;
    }
};

class getRequest {
public:
    httpRequest get_request;

    void set_value(std::string &time) {
        get_request.method = "GET";
        get_request.path   = "/mycontainers3";
        get_request.protocol_version = "HTTP/1.1";
        get_request.headers.emplace("Host", "10.239.241.160:8000");
        get_request.headers.emplace("Accept-Encoding", "identity");
        get_request.headers.emplace("Content-Length", "0");
        get_request.headers.emplace(std::string("x-amz-date"), time);
        std::string sign = get_request.auth();
        get_request.headers.emplace(std::string("Authorization"), std::string("AWS 0555b35654ad1656d804:"+sign));
    }

    std::string get_value() {
        return get_request.get_request();
    }

};








int main(int argc, char* argv[]) {
//    if(argc != 2) {
//        std::cerr << "Usage: "<< argv[0] <<" <host>" << std::endl;
//        return 1;
//    }

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
        std::cout << "time: " << time << std::endl;


        getRequest get_request;
        get_request.set_value(time);
        const auto request = get_request.get_value();

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
