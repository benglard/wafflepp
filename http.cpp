#define HTTPSERVER_IMPL

#include "httpserver.h"
#include "json.hpp"
#include "render.hpp"

#include <iostream>
#include <sstream>
#include <memory>
#include <unordered_map>
#include <functional>
#include <csignal>
#include <regex>
#include <random>

namespace wafflepp
{
  namespace helpers
  {
    inline unsigned char fromHex(unsigned char ch)
    {
      if (ch <= '9' && ch >= '0')
      {
        ch -= '0';
      }
      else if (ch <= 'f' && ch >= 'a')
      {
        ch -= 'a' - 10;
      }
      else if (ch <= 'F' && ch >= 'A')
      {
        ch -= 'A' - 10;
      }
      else
      {
        ch = 0;
      }
      return ch;
    }

    const std::string urldecode(const std::string &str)
    {
      // based on http://dlib.net/dlib/server/server_http.cpp.html
      std::string result;
      const std::size_t str_size = str.size();
      for (std::size_t i{0}; i < str_size; ++i)
      {
        if (str[i] == '+')
        {
          result += ' ';
        }
        else if (str[i] == '%' && str_size > i + 2)
        {
          const unsigned char ch1 = fromHex(str[i + 1]);
          const unsigned char ch2 = fromHex(str[i + 2]);
          const unsigned char ch = (ch1 << 4) | ch2;
          result += ch;
          i += 2;
        }
        else
        {
          result += str[i];
        }
      }
      return result;
    }

    inline std::string uuid4()
    {
      static std::random_device rd;
      static std::mt19937 gen(rd());
      static std::uniform_int_distribution<> dis(0, 15);
      static std::uniform_int_distribution<> dis2(8, 11);

      std::stringstream ss;
      int i;
      ss << std::hex;
      for (i = 0; i < 8; i++)
      {
        ss << dis(gen);
      }
      ss << "-";
      for (i = 0; i < 4; i++)
      {
        ss << dis(gen);
      }
      ss << "-4";
      for (i = 0; i < 3; i++)
      {
        ss << dis(gen);
      }
      ss << "-";
      ss << dis2(gen);
      for (i = 0; i < 3; i++)
      {
        ss << dis(gen);
      }
      ss << "-";
      for (i = 0; i < 12; i++)
      {
        ss << dis(gen);
      };
      return ss.str();
    }

  } // namespace helpers

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
    std::string content_type{};
    bool is_json{false};
    bool is_multipart_form{false};
    nlohmann::json json{};

    std::vector<std::string> params{};
    std::unordered_map<std::string, std::string> args{};
    std::unordered_map<std::string, std::string> cookies{};

    struct FormItem
    {
      FormItem() {}
      FormItem(const std::string &data_) : data(data_) {}
      void setContentType(const std::string &content)
      {
        content_type = content;
        binary = content.find("text") == std::string::npos;
      }

      std::string disposition{};
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
      cookies.reserve(DEFAULT_ARG_VEC_CAPACITY);
      form.reserve(DEFAULT_ARG_VEC_CAPACITY);

      parseContentType();
      parseJsonBody();
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

    std::string cookie(const std::string &key,
                       const std::string &default_value)
    {
      const auto &val = cookies.find(key);
      if (val == cookies.end())
      {
        return default_value;
      }
      else
      {
        return val->second;
      }
    }

  private:
    void parseContentType()
    {
      const auto raw = http_request_header(request, "Content-Type");
      content_type = std::string(raw.buf, raw.len);
      if (content_type == "application/json")
      {
        is_json = true;
      }
      else if (content_type.find("multipart/form-data") == 0)
      {
        is_multipart_form = true;
      }
    }

    void parseJsonBody()
    {
      if (is_json)
      {
        try
        {
          json = nlohmann::json::parse(body);
        }
        catch (...)
        {
        }
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

        auto trim_key{key};
        // trim leading spaces
        trim_key.erase(trim_key.begin(), std::find_if(trim_key.begin(), trim_key.end(), [](int ch) {
                         return !std::isspace(ch);
                       }));

        cookies[trim_key] = value;

        start = pos_semi + 1;
      }
    }

    void parseForm()
    {
      if (is_json)
      {
        return;
      }

      if (is_multipart_form)
      {
        parseMultipartForm();
      }
      else
      {
        parseURLEncodedForm();
      }
    }

    void parseURLEncodedForm()
    {
      const std::size_t body_size = body.size();
      if (body_size == 0)
      {
        return;
      }

      auto start = 0UL;
      while (start < body_size)
      {
        const auto pos_eq = body.find("=", start);
        if (pos_eq == std::string::npos)
        {
          break;
        }

        const auto &key = body.substr(start, pos_eq - start);

        auto pos_amp = body.find("&", start);
        if (pos_amp == std::string::npos)
        {
          pos_amp = body_size;
        }

        start = pos_eq + 1;

        const auto &value = body.substr(start, pos_amp - start);

        form.emplace(key, helpers::urldecode(value));

        start = pos_amp + 1;
      }
    }

    void parseMultipartForm()
    {
      const std::size_t body_size = body.size();
      if (body_size == 0)
      {
        return;
      }

      std::smatch boundary_matches{};
      std::string boundary{};
      if (std::regex_match(content_type, boundary_matches,
                           std::regex("^multipart/form-data; boundary=(.*)")))
      {
        if (boundary_matches.size() > 1)
        {
          boundary = boundary_matches[1].str();
        }
      }

      if (boundary.empty())
      {
        return;
      }

      const std::size_t boundary_size = boundary.size();
      auto start = boundary_size + 4;

      while (start < body_size)
      {
        const auto pos_boundary = body.find(boundary, start);
        if (pos_boundary == std::string::npos)
        {
          break;
        }

        auto start1 = 0UL;
        auto end1 = start;

        FormItem form_item{};

        const std::string CONTENT_DISP_STRING{"Content-Disposition: "};
        start1 = body.find(CONTENT_DISP_STRING, end1);
        if (start1 == std::string::npos)
        {
          break;
        }
        start1 += CONTENT_DISP_STRING.size();

        end1 = body.find(";", start1);
        if (end1 == std::string::npos)
        {
          break;
        }

        form_item.disposition = body.substr(start1, end1 - start1);

        if (form_item.disposition == "form-data")
        {

          const std::string NAME_STRING{"name=\""};
          start1 = body.find(NAME_STRING, end1);
          if (start1 == std::string::npos)
          {
            break;
          }
          start1 += NAME_STRING.size();

          end1 = body.find("\"", start1);
          if (end1 == std::string::npos)
          {
            break;
          }

          const auto &name = body.substr(start1, end1 - start1);

          if (body[end1 + 1] == ';')
          {
            const std::string FILENAME_STRING{"; filename=\""};
            start1 = body.find(FILENAME_STRING, end1);
            if (start1 != std::string::npos)
            {
              start1 += FILENAME_STRING.size();
              end1 = body.find("\"", start1);
              if (end1 == std::string::npos)
              {
                break;
              }

              form_item.filename = body.substr(start1, end1 - start1);
            }

            const std::string CONTENT_TYPE_STRING{"Content-Type: "};
            start1 = body.find(CONTENT_TYPE_STRING, end1);
            if (start1 != std::string::npos)
            {
              start1 += CONTENT_TYPE_STRING.size();
              end1 = body.find("\r", start1);
              if (end1 == std::string::npos)
              {
                break;
              }

              form_item.setContentType(body.substr(start1, end1 - start1));
            }
          }
          else
          {
            ++end1;
          }

          start1 = end1 + 4;
          form_item.data = body.substr(start1, pos_boundary - start1 - 4);

          form.emplace(name, form_item);
        }
        else
        {
          // TODO handle Content-Disposition not "form-data"
        }

        start = pos_boundary + boundary_size + 2;
      }
    }
  };
  struct Response
  {
    http_response_s *response{nullptr};
    std::vector<Cookie> cookies{};
    bool finished{false};

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
      if (description.empty())
      {
        this->body(status_text[status]);
      }
      else
      {
        this->body(description);
      }

      return this->status(status);
    }
    void finish(const std::unique_ptr<Request> &req)
    {
      if (finished)
      {
        return;
      }

      const auto &cookie = buildCookieString();
      if (!cookie.empty())
      {
        http_response_header(response, "Set-Cookie", cookie.c_str());
      }
      http_respond(req->request, response);
      finished = true;
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
    Response *clearCookies(const std::unordered_map<std::string, std::string> &cookies)
    {
      for (const auto &cookie : cookies)
      {
        deleteCookie(cookie.first);
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

              if (!res->finished)
              {
                res->finish(req);
              }
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

  struct BaseSession
  {
    virtual std::string get(const std::unique_ptr<wafflepp::Request> &req,
                            const std::unique_ptr<wafflepp::Response> &res,
                            const std::string &key,
                            const std::string &default_value) = 0;

    virtual void set(const std::unique_ptr<wafflepp::Request> &req,
                     const std::unique_ptr<wafflepp::Response> &res,
                     const std::string &key,
                     const std::string &value) = 0;

    virtual void deleteKey(const std::unique_ptr<wafflepp::Request> &req,
                           const std::unique_ptr<wafflepp::Response> &res,
                           const std::string &key) = 0;

    virtual void flush(const std::unique_ptr<wafflepp::Request> &req,
                       const std::unique_ptr<wafflepp::Response> &res) = 0;

    virtual ~BaseSession() = default;

  protected:
    std::string uid(const std::unique_ptr<wafflepp::Request> &req,
                    const std::unique_ptr<wafflepp::Response> &res) const
    {
      constexpr const char *KEY{"sid"};
      constexpr const char *DEFAULT{""};
      const auto &cookie = req->cookie(KEY, DEFAULT);
      if (cookie.empty())
      {
        const auto &id = helpers::uuid4();
        res->cookie(KEY, id);
        return id;
      }
      else
      {
        return cookie;
      }
    }
  };

  struct MemorySession final : public BaseSession
  {
    std::string get(const std::unique_ptr<wafflepp::Request> &req,
                    const std::unique_ptr<wafflepp::Response> &res,
                    const std::string &key,
                    const std::string &default_value) override
    {
      auto &db = data_[uid(req, res)];
      const auto &val = db.find(key);
      if (val == db.end())
      {
        return default_value;
      }
      else
      {
        return val->second;
      }
    }

    void set(const std::unique_ptr<wafflepp::Request> &req,
             const std::unique_ptr<wafflepp::Response> &res,
             const std::string &key,
             const std::string &value) override
    {
      data_[uid(req, res)][key] = value;
    }

    void deleteKey(const std::unique_ptr<wafflepp::Request> &req,
                   const std::unique_ptr<wafflepp::Response> &res,
                   const std::string &key) override
    {
      data_[uid(req, res)].erase(key);
    }

    void flush(const std::unique_ptr<wafflepp::Request> &req,
               const std::unique_ptr<wafflepp::Response> &res) override
    {
      data_[uid(req, res)].clear();
    }

  private:
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> data_{};
  };

  struct CookieSession final : public BaseSession
  {
    std::string get(const std::unique_ptr<wafflepp::Request> &req,
                    const std::unique_ptr<wafflepp::Response> &res,
                    const std::string &key,
                    const std::string &default_value) override
    {
      (void)res;
      return req->cookie(key, default_value);
    }

    void set(const std::unique_ptr<wafflepp::Request> &req,
             const std::unique_ptr<wafflepp::Response> &res,
             const std::string &key,
             const std::string &value) override
    {
      (void)req;
      res->cookie(key, value);
    }

    void deleteKey(const std::unique_ptr<wafflepp::Request> &req,
                   const std::unique_ptr<wafflepp::Response> &res,
                   const std::string &key) override
    {
      (void)req;
      res->deleteCookie(key);
    }

    void flush(const std::unique_ptr<wafflepp::Request> &req,
               const std::unique_ptr<wafflepp::Response> &res) override
    {
      res->clearCookies(req->cookies);
    }
  };

  struct Server
  {
  public:
    Server(std::unique_ptr<BaseSession> &&sess) : session(std::move(sess)) {}

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

    std::unique_ptr<BaseSession> session;
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
  auto memory_session = std::make_unique<wafflepp::MemorySession>();
  auto cookie_session = std::make_unique<wafflepp::CookieSession>();

  wafflepp::Server app(std::move(cookie_session));

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

  app.post("/json",
           [](const std::unique_ptr<wafflepp::Request> &req,
              const std::unique_ptr<wafflepp::Response> &res) {
             std::cout << req->json << std::endl;
             (void)res;
           });

  app.get("/error",
          [](const std::unique_ptr<wafflepp::Request> &req,
             const std::unique_ptr<wafflepp::Response> &res) {
            int a = std::stoi(" "); // force an error
            (void)a;
            (void)req;
            (void)res;
          });

  app.post("/form",
           [](const std::unique_ptr<wafflepp::Request> &req,
              const std::unique_ptr<wafflepp::Response> &res) {
             for (const auto &item : req->form)
             {
               std::cout << item.first << ": "
                         << item.second.data << " "
                         << item.second.filename << " "
                         << item.second.content_type
                         << std::endl;
             }

             res->body("Uploaded!")->finish(req);
           });

  app.get("/render",
          [](const std::unique_ptr<wafflepp::Request> &req,
             const std::unique_ptr<wafflepp::Response> &res) {
            using namespace htmlpp;
            res
                ->content("text/html")
                ->body(
                    html(
                        head(title("Title")),
                        body(p("Hello World!"))))
                ->finish(req);
          });

  app.get("/form",
          [](const std::unique_ptr<wafflepp::Request> &req,
             const std::unique_ptr<wafflepp::Response> &res) {
            using namespace htmlpp;
            res
                ->content("text/html")
                ->body(
                    html(body(form(
                        {{"action", "/form"},
                         {"method", "POST"},
                         {"enctype", "multipart/form-data"}},
                        p(input(
                            {{"type", "text"},
                             {"name", "firstname"},
                             {"placeholder", "First Name"}})),
                        p(input(
                            {{"type", "text"},
                             {"name", "lastname"},
                             {"placeholder", "Last Name"}})),
                        p(input(
                            {{"type", "file"},
                             {"name", "file"}})),
                        p(input(
                            {{"type", "submit"}}, "Upload"))))))
                ->finish(req);
          });

  app.get("/sesh",
          [&app](const std::unique_ptr<wafflepp::Request> &req,
                 const std::unique_ptr<wafflepp::Response> &res) {
            using namespace htmlpp;
            const auto &n = app.session->get(req, res, "test", "0");
            app.session->set(req, res, "test", std::to_string(std::stoi(n) + 1));
            res
                ->content("text/html")
                ->body(html(body("n = ", n)))
                ->finish(req);
          });

  app.listen(8080);
}
