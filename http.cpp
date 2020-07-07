#define HTTPSERVER_IMPL

#include "httpserver.h"
#include "json.hpp"

#include <iostream>
#include <sstream>
#include <memory>
#include <unordered_map>
#include <functional>
#include <csignal>
#include <regex>

namespace wafflepp
{
  struct Cookie
  {
    Cookie(const std::string &key_, const std::string &value_)
        : key(key_), value(value_)
    {
    }

    Cookie(const std::string &key_, const std::string &value_,
           const std::string &expires_, const std::string &path_)
        : key(key_), value(value_), expires(expires_), path(path_)
    {
    }

    std::string key{};
    std::string value{};
    std::string expires{};
    std::string path{};
  };

  struct Request
  {
    http_request_s *request{nullptr};
    std::string method{};
    std::string url{};
    std::string body{};
    std::vector<std::string> params{};
    std::unordered_map<std::string, std::string> args{};
    std::vector<Cookie> cookies{};

    struct FormItem
    {
      std::string data{};
      std::string content_type{};
      std::string filename{};
      bool binary{false};
    };
    std::unordered_map<std::string, FormItem> form{};

    Request(http_request_s *request_)
    {
      request = request_;

      auto http_method = http_request_method(request);
      auto http_url = http_request_target(request);
      auto http_body = http_request_body(request);

      method = std::string(http_method.buf, http_method.len);
      url = std::string(http_url.buf, http_url.len);
      body = std::string(http_body.buf, http_body.len);

      constexpr std::size_t DEFAULT_ARG_VEC_CAPACITY{5};
      params.reserve(DEFAULT_ARG_VEC_CAPACITY);
      args.reserve(DEFAULT_ARG_VEC_CAPACITY);

      parseQuery();
      parseCookies();
      parseForm();
    }

    Request *connection(int directive)
    {
      http_request_connection(request, directive);
      return this;
    }

    void parseParams(const std::smatch &matches)
    {
      const std::size_t num_matches{matches.size()};
      for (std::size_t match_index{1}; match_index < num_matches; ++match_index)
      {
        const std::ssub_match &sub_match = matches[match_index];
        params.emplace_back(sub_match.str());
      }
    }

    void parseQuery()
    {
      const std::size_t pos_qmark = url.find("?");
      if (pos_qmark == std::string::npos)
      {
        return;
      }

      std::size_t start = pos_qmark + 1;
      const std::size_t url_size = url.size();
      while (start < url_size)
      {
        const auto pos_eq = url.find("=", start);
        if (pos_eq == std::string::npos)
        {
          break;
        }

        const auto &key = url.substr(start, pos_eq - start);

        auto pos_amp = url.find("&", start);
        if (pos_amp == std::string::npos)
        {
          pos_amp = url_size;
        }

        start = pos_eq + 1;

        const auto &value = url.substr(start, pos_amp - start);

        args[key] = value;

        start = pos_amp + 1;
      }
    }

    void parseCookies()
    {
      const auto raw = http_request_header(request, "cookie");
      const auto cookie = std::string(raw.buf, raw.len);
      auto start = 0;
      while (start < raw.len)
      {
        const auto pos_eq = cookie.find("=", start);
        if (pos_eq == std::string::npos)
        {
          break;
        }

        const auto &key = cookie.substr(start, pos_eq - start);

        auto pos_semi = cookie.find(";", start);
        if (pos_semi == std::string::npos)
        {
          pos_semi = raw.len;
        }

        start = pos_eq + 1;

        const auto &value = cookie.substr(start, pos_semi - start);

        cookies.emplace_back(key, value);

        start = pos_semi + 1;
      }
    }

    void parseForm() {}
  };
  struct Response
  {
    http_response_s *response{nullptr};
    std::vector<Cookie> cookies{};

    Response()
    {
      response = http_response_init();
    }
    Response *body(std::string &&str)
    {
      http_response_body(response, str.c_str(), str.size());
      return this;
    }
    Response *body(const std::string &str)
    {
      http_response_body(response, str.c_str(), str.size());
      return this;
    }
    Response *header(const char *key, const char *value)
    {
      http_response_header(response, key, value);
      return this;
    }
    Response *status(int status)
    {
      http_response_status(response, status);
      return this;
    }
    Response *location(const std::string &url)
    {
      return this->header("Location", url.c_str());
    }
    Response *redirect(const std::string &url)
    {
      return this->status(302)->location(url);
    }
    Response *content(const char *content_type)
    {
      return this->header("Content-Type", content_type);
    }
    Response *json(const nlohmann::json &json)
    {
      return this->content("application/json")->body(json.dump());
    }
    Response *abort(int status, const std::string &description = "")
    {
      this->status(status)->content("text/html");

      if (description.empty())
      {
        this->body(status_text[status]);
      }
      else
      {
        this->body(description);
      }

      return this;
    }
    void finish(const std::unique_ptr<Request> &req)
    {
      const auto &cookie = buildCookieString();
      if (!cookie.empty())
      {
        http_response_header(response, "Set-Cookie", cookie.c_str());
      }
      http_respond(req->request, response);
    }

    Response *cookie(const std::string &key, const std::string &value,
                     const std::string &expires = "", const std::string &path = "/")
    {
      cookies.emplace_back(key, value, expires, path);
      return this;
    }
    Response *deleteCookie(const std::string &key, const std::string &path = "/")
    {
      return this->cookie(key, "", "Thu, 01 Jan 1970 00:00:00 UTC", path);
    }
    Response *clearCookies(const std::vector<Cookie> &cookies)
    {
      for (const auto &cookie : cookies)
      {
        deleteCookie(cookie.key, cookie.path);
      }
      return this;
    }

  private:
    std::string buildCookieString()
    {
      const std::size_t num_cookies(cookies.size());
      if (num_cookies == 0)
      {
        return "";
      }

      std::stringstream cookie_str;

      std::size_t cookie_index{0};
      for (const auto &cookie : cookies)
      {
        cookie_str << cookie.key << "=" << cookie.value << ";";

        if (!cookie.expires.empty())
        {
          cookie_str << "expires=" << cookie.expires << ";";
        }
        cookie_str << "Path=" << cookie.path;

        if (cookie_index < num_cookies - 1)
        {
          cookie_str << "&";
        }

        ++cookie_index;
      }

      return cookie_str.str();
    }
  };

  using URLCallback = std::function<void(
      const std::unique_ptr<wafflepp::Request> &req,
      const std::unique_ptr<wafflepp::Response> &res)>;
  std::unordered_map<std::string, std::unordered_map<std::string, URLCallback>> callbacks{};
  struct http_server_s *server{nullptr};

  namespace helpers
  {
    inline bool matchURL(const std::string &pattern, const std::unique_ptr<Request> &req)
    {
      std::smatch matches{};
      if (std::regex_match(req->url, matches, std::regex(pattern)))
      {
        req->parseParams(matches);
        return true;
      }

      return false;
    }

    inline void requestHandler(http_request_s *request)
    {
      const auto req = std::make_unique<Request>(request);
      const auto res = std::make_unique<Response>();

      for (const auto &patterns : callbacks)
      {
        if (matchURL(patterns.first, req))
        {
          const auto &methods = patterns.second;
          const auto &fn = methods.find(req->method);

          if (fn == methods.end())
          {
            res->abort(403)->finish(req);
          }
          else
          {
            try
            {
              fn->second(req, res);
            }
            catch (const std::exception &err)
            {
              res->abort(500, err.what())->finish(req);
            }
          }

          return;
        }
      }

      res->abort(404)->finish(req);
    }

    void exitHandler(int signal)
    {
      std::cout << "exiting with signal " << signal << std::endl;
      free(server);
      exit(0);
    }
  } // namespace helpers

  struct Server
  {
  public:
    Server(){};

    void listen(int port)
    {
      signal(SIGTERM, helpers::exitHandler);
      signal(SIGINT, helpers::exitHandler);

      server = http_server_init(port, helpers::requestHandler);
      http_server_listen(server);
    }

    // HEAD = 0,
    // GET = 1,
    // POST = 2,
    // DELETE = 3,
    // PATCH = 4,
    // PUT = 5,
    // OPTIONS = 6,

#define ADD_METHOD(method_name, method)               \
  void method_name(const char *url, URLCallback &&cb) \
  {                                                   \
    std::string full_url{url};                        \
    full_url.append(".*");                            \
    callbacks[full_url][#method] = cb;                \
  }

    ADD_METHOD(head, HEAD)
    ADD_METHOD(get, GET)
    ADD_METHOD(post, POST)
    ADD_METHOD(hdelete, DELETE)
    ADD_METHOD(patch, PATCH)
    ADD_METHOD(put, PUT)
    ADD_METHOD(options, OPTIONS)
  };

} // namespace wafflepp

inline int fib(int n)
{
  if (n <= 1)
    return n;
  return fib(n - 1) + fib(n - 2);
}

int main()
{
  wafflepp::Server app;

  app.get("/([0-9]+)",
          [](const std::unique_ptr<wafflepp::Request> &req,
             const std::unique_ptr<wafflepp::Response> &res) {
            const auto n = std::stoi(req->params[0]);
            std::stringstream ss;
            ss << "waffle++<hr> fib(" << n << "): " << fib(n);

            res
                ->cookie("test", "test")
                ->status(200)
                ->content("text/html")
                ->body(ss.str())
                ->finish(req);
          });

  app.get("/search",
          [](const std::unique_ptr<wafflepp::Request> &req,
             const std::unique_ptr<wafflepp::Response> &res) {
            res->redirect("https://www.google.com/search?q=" + req->args["q"])->finish(req);
          });

  app.get("/json",
          [](const std::unique_ptr<wafflepp::Request> &req,
             const std::unique_ptr<wafflepp::Response> &res) {
            res->json({{"key", "value"}})->finish(req);
          });

  app.get("/error",
          [](const std::unique_ptr<wafflepp::Request> &req,
             const std::unique_ptr<wafflepp::Response> &res) {
            int a = std::stoi(" "); // force an error
            (void)a;
            (void)req;
            (void)res;
          });

  app.listen(8080);
}
