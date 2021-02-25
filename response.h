#ifndef _RESPONSE_H_
#define _RESPONSE_H_

#include <string>
#include <map>

#include <boost/asio.hpp>

class httpResponse {
public:
    std::string version;
    std::string status;
    std::string reason_phrase;
    std::map<std::string, std::string> headers;
    std::string body;
    // std::string ;

    void read_header(boost::asio::ip::tcp::socket& socket) {
        boost::array<char, 65536> buf;
        boost::system::error_code ec;
        size_t len = socket.read_some(boost::asio::buffer(buf), ec);
        

        std::string header(buf.data(), len);
        std::size_t position = header.find("\n");
        std::stringstream ss(header.substr(0,position));

                
        
    }


};
#endif // _RESPONSE_H_