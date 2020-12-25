#include "s3_hmac.h"
#include "Base64.h"
#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <string>
#include <istream>
#include <ostream>

using boost::asio::ip::tcp;

std::string localtime() {
   time_t rawtime;
   struct tm *info;
   char buffer[32];
   time( &rawtime );
   info = gmtime( &rawtime );
   strftime(buffer, 80, "%a, %d %b %Y %H:%M:%S +0000", info);
   return std::string(buffer);
}

const char* access_key = "0555b35654ad1656d804";
const char* secret_key = "h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==";
std::string auth(std::string time) {
    std::stringstream ss;
    ss << "GET\n"
       << "\n"
       << "\n"
       << "\n"
       << "x-amz-date:" << time << "\n"
       << "/";
  const auto signature = ss.str();
  std::cout << "string_to_sign: \n" << signature << std::endl;
  HMAC_SHA1 hmac_sha1(secret_key, strlen(secret_key));
  hmac_sha1.Update(signature.c_str(), signature.size());
  char result[32];
  int reslen = hmac_sha1.Final(result);
  std::string ret = macaron::Base64::Encode(std::string(result, reslen));
  return ret;
}

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
        std::string sign = auth(time);
        std::cout << "sign: " << sign << std::endl;
        std::stringstream request_stream;
        request_stream << "GET / HTTP/1.1\r\n"
                       << "Host: " << "10.239.241.160:8000" << "\r\n"
                       << "Accept-Encoding: identity\r\n"
                       << "Content-Length: 0\r\n"
                       << "x-amz-date: " << time << "\r\n"
                       << "Authorization: AWS 0555b35654ad1656d804:" << sign << "\r\n"
                       << "\r\n";
        const auto request = request_stream.str();

        boost::asio::write(socket, boost::asio::buffer(request), ec);

        // method 1 to read
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
