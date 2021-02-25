#ifndef _COMMON_H_
#define _COMMON_H_

#include <string>

class s3Time {
public:
    static std::string get_v2();
    static std::string get_v4();
};

namespace detail {

// helpers for string_join_reserve()
static inline void join_next(std::string& s, const std::string_view& d) {}
template <typename... Args>
void join_next(std::string& s, const std::string_view& d,
               const std::string_view& v, const Args&... args)
{
  s.append(d.begin(), d.end());
  s.append(v.begin(), v.end());
  join_next(s, d, args...);
}

static inline void join(std::string& s, const std::string_view& d) {}
template <typename... Args>
void join(std::string& s, const std::string_view& d,
          const std::string_view& v, const Args&... args)
{
  s.append(v.begin(), v.end());
  join_next(s, d, args...);
}

// variadic sum() to add up string lengths for reserve()
static inline constexpr size_t sum() { return 0; }
template <typename T, typename... Args>
constexpr size_t sum(T& v, Args... args) { return v.size() + sum(args...); }

/// joins the given string arguments with a delimiter, returning as a
/// std::string that gets preallocated with reserve()
template <typename... Args>
std::string string_join_reserve(const std::string_view& delim,
                                const Args&... args)
{
  size_t delim_size = delim.size() * std::max<ssize_t>(0, sizeof...(args) - 1);
  size_t total_size = detail::sum(args...) + delim_size;
  std::string result;
  result.reserve(total_size);
  detail::join(result, delim, args...);
  return result;
}
template <typename... Args>
std::string string_join_reserve(char delim, const Args&... args)
{
  return string_join_reserve(std::string_view{&delim, 1}, args...);
}

}
#endif // _COMMON_H_