#ifndef _COMMON_H_
#define _COMMON_H_

#include <string>

class s3Time {
public:
    static std::string get_v2();
    static std::string get_v4();
};

#endif // _COMMON_H_