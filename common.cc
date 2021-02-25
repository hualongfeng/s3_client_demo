#include "common.h"


std::string s3Time::get_v2() {
    time_t rawtime;
    time(&rawtime);
    auto utc_time = gmtime(&rawtime);
    char buffer[32];
    //strftime(buffer, 80, "%a, %d %b %Y %H:%M:%S +0000", info);
    strftime(buffer, 32, "%a, %d %b %Y %H:%M:%S %Z", utc_time);
    return std::string(buffer);
}

std::string s3Time::get_v4() {
    time_t rawtime;
    time(&rawtime);
    auto utc_time = gmtime(&rawtime);
    char buffer[32];
    strftime(buffer, 80, "%Y%m%dT%H%M%SZ", utc_time);
    return std::string(buffer);
}

