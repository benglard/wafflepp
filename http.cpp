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
#include <thread>

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

    static char encoding_table[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/'};

    static int mod_table[] = {0, 2, 1};

    inline unsigned int rol(
        const unsigned int value,
        const unsigned int steps)
    {
      return ((value << steps) | (value >> (32 - steps)));
    }

    inline void clearbuffer(unsigned int *buffer)
    {
      int pos = 16;
      for (; --pos >= 0;)
      {
        buffer[pos] = 0;
      }
    }

    inline void innerhash(unsigned int *result, unsigned int *w)
    {
      unsigned int
          a = result[0],
          b = result[1], c = result[2],
          d = result[3], e = result[4];
      int round = 0;
#define sha1macro(func, val)                                        \
  {                                                                 \
    const unsigned int t = rol(a, 5) + (func) + e + val + w[round]; \
    e = d;                                                          \
    d = c;                                                          \
    c = rol(b, 30);                                                 \
    b = a;                                                          \
    a = t;                                                          \
  }
      while (round < 16)
      {
        sha1macro((b & c) | (~b & d), 0x5a827999)++ round;
      }
      while (round < 20)
      {
        w[round] = rol(
            (w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
        sha1macro((b & c) | (~b & d), 0x5a827999)++ round;
      }
      while (round < 40)
      {
        w[round] = rol(
            (w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
        sha1macro(b ^ c ^ d, 0x6ed9eba1)++ round;
      }
      while (round < 60)
      {
        w[round] = rol(
            (w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
        sha1macro((b & c) | (b & d) | (c & d), 0x8f1bbcdc)++ round;
      }
      while (round < 80)
      {
        w[round] = rol(
            (w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
        sha1macro(b ^ c ^ d, 0xca62c1d6)++ round;
      }
#undef sha1macro
      result[0] += a;
      result[1] += b;
      result[2] += c;
      result[3] += d;
      result[4] += e;
    }

    inline void sha1b64(const char *src, char *dest)
    {
      // sha1 hash
      int bytelength = strlen(src);
      unsigned int result[5] = {
          0x67452301, 0xefcdab89, 0x98badcfe,
          0x10325476, 0xc3d2e1f0};
      const unsigned char *sarray = (const unsigned char *)src;
      unsigned int w[80];

      const int end_full_blocks = bytelength - 64;
      int curblock = 0, end_cur_block;

      while (curblock <= end_full_blocks)
      {
        end_cur_block = curblock + 64;
        int roundpos = 0;
        for (; curblock < end_cur_block; curblock += 4)
        {
          w[roundpos++] = (unsigned int)sarray[curblock + 3] | (((unsigned int)sarray[curblock + 2]) << 8) | (((unsigned int)sarray[curblock + 1]) << 16) | (((unsigned int)sarray[curblock]) << 24);
        }
        innerhash(result, w);
      }

      end_cur_block = bytelength - curblock;
      clearbuffer(w);
      int lastbytes = 0;
      for (; lastbytes < end_cur_block; ++lastbytes)
      {
        w[lastbytes >> 2] |= (unsigned int)
                                 sarray[lastbytes + curblock]
                             << ((3 - (lastbytes & 3)) << 3);
      }
      w[lastbytes >> 2] |= 0x80 << ((3 - (lastbytes & 3)) << 3);

      if (end_cur_block >= 56)
      {
        innerhash(result, w);
        clearbuffer(w);
      }

      w[15] = bytelength << 3;
      innerhash(result, w);

      unsigned char hash[20];
      int hashbyte = 20;
      for (; --hashbyte >= 0;)
      {
        hash[hashbyte] = (result[hashbyte >> 2] >> (((3 - hashbyte) & 0x3) << 3)) & 0xff;
      }

      // Base64 encode
      int i = 0;
      int j = 0;
      while (i < 20)
      {
        uint32_t octet_a = i < 20 ? hash[i++] : 0;
        uint32_t octet_b = i < 20 ? hash[i++] : 0;
        uint32_t octet_c = i < 20 ? hash[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        dest[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        dest[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        dest[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        dest[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
      }
      for (i = 0; i < mod_table[20 % 3]; ++i)
      {
        dest[28 - 1 - i] = '=';
      }
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

    std::string header(const char *key) const
    {
      const auto raw = http_request_header(request, key);
      if (raw.buf == nullptr || raw.len == 0)
      {
        return "";
      }
      else
      {
        return std::string(raw.buf, raw.len);
      }
    }

  private:
    void parseContentType()
    {
      const auto content_type = header("Content-Type");
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

        cookies[key] = value;

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

  private:
    std::string buildCookieString() const
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

  constexpr const char *MAGIC{"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"};

  struct WebSocket
  {
    struct Message
    {
      std::string data{};
      int type{-1};
      int code{-1};
    };

    static const int TYPE_CONTINUATION{0x0};
    static const int TYPE_TEXT{0x1};
    static const int TYPE_BINARY{0x2};
    static const int TYPE_CLOSE{0x3};
    static const int TYPE_PING{0x4};
    static const int TYPE_PONG{0x5};

    void open(const std::unique_ptr<Request> &req, const std::unique_ptr<Response> &res)
    {
      if (req->header("Upgrade") != "websocket")
      {
        res->status(403)->body("Can upgrade only to websocket")->finish(req);
        return;
      }

      const std::string &origin = req->header("Origin");
      if (!origin.empty() && !this->checkorigin(origin))
      {
        res->status(403)->body("Cross origin websockets not allowed")->finish(req);
        return;
      }
      else
      {
        const std::string &ws_origin = req->header("Sec-WebSocket-Origin");

        if (!ws_origin.empty() && !this->checkorigin(ws_origin))
        {
          res->status(403)->body("Cross origin websockets not allowed")->finish(req);
          return;
        }
      }

      const std::string &protocol = req->header("Sec-WebSocket-Protocol");
      if (!protocol.empty())
      {
        const auto pos_comma = protocol.find(",");
        const auto first_proto = protocol.substr(0, pos_comma);
        res->header("Sec-WebSocket-Protocol", first_proto.c_str());
      }

      const std::string &key = req->header("Sec-WebSocket-Key");
      const std::string outkey{key + MAGIC};
      std::array<char, 28> b64 = {0};
      helpers::sha1b64(outkey.c_str(), b64.data());

      res
          ->status(101)
          ->body("")
          ->header("Upgrade", "websocket")
          ->header("Connection", "Upgrade")
          ->header("Sec-WebSocket-Accept", b64.data())
          ->finish(req);

      if (res->finished)
      {
        try
        {
          this->onopen(req);
          opened = true;
        }
        catch (...)
        {
        }
      }

      // TODO listen for socket updates
    };

    void close(int code = 0, const std::string &msg = "")
    {
      if (!opened)
      {
        return;
      }
      try
      {
        this->onclose(); // how to pass req?
      }
      catch (...)
      {
        return;
      }

      std::string payload{};
      if (code && code < 0x7fff)
      {
        int sentinel = ((code >> 8) & 0xff) & (code & 0xff);
        payload = (char)sentinel + msg;
      }

      this->sendFrame(true, 0x8, payload);

      // TODO close socket
    }

    void write(const std::string &data, bool binary = false) const
    {
      if (!opened)
      {
        return;
      }
      this->sendFrame(true, binary ? 0x2 : 0x1, data);
    }

    void ping(const std::string &data) const
    {
      if (!opened)
      {
        return;
      }
      this->sendFrame(true, 0x9, data);
    }

    bool opened{false};
    std::function<bool(const std::string &)> checkorigin{};
    std::function<void(const std::unique_ptr<Request> &)> onopen{};
    std::function<void(const Message &)> onmessage{};
    std::function<void(const Message &)> onpong{};
    std::function<void(/*const std::unique_ptr<Request> &*/)> onclose{};

  private:
    void sendFrame(bool finish, int opcode, const std::string &payload,
                   std::size_t maxlen = 65535, bool mask = false) const
    {
      (void)finish;
      (void)opcode;
      (void)payload;
      (void)maxlen;
      (void)mask;

      // TODO build and send message
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

    using WebSocketCallback = std::function<void(const std::unique_ptr<wafflepp::WebSocket> &)>;
    void ws(const char *url, const WebSocketCallback &cb)
    {
      get(url, [&cb](const std::unique_ptr<wafflepp::Request> &req,
                     const std::unique_ptr<wafflepp::Response> &res) {
        auto ws = std::make_unique<WebSocket>();

        try
        {
          cb(ws);
          ws->open(req, res);
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        catch (const std::exception &err)
        {
          res->abort(500, err.what())->finish(req);
        }
      });
    }
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

  app.post("/json",
           [](const std::unique_ptr<wafflepp::Request> &req,
              const std::unique_ptr<wafflepp::Response> &res) {
             std::cout << req->json << std::endl;
             (void)res;
           });

  app.get("/error",
          [](const std::unique_ptr<wafflepp::Request> &,
             const std::unique_ptr<wafflepp::Response> &) {
            int a = std::stoi(" "); // force an error
            (void)a;
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

  app.get("/ws",
          [](const std::unique_ptr<wafflepp::Request> &req,
             const std::unique_ptr<wafflepp::Response> &res) {
            const char *js =
                "var ws = new WebSocket(\"ws://localhost:8080/iws\");\n"
                "function print() { console.log(ws.readyState); }\n"
                "ws.onopen = function()\n"
                "{\n"
                "  console.log(\"opened\");\n"
                "  print();\n"
                "  ws.send(\"Hello\");\n"
                "}\n"
                "ws.onmessage = function(msg)\n"
                "{\n"
                "  console.log(msg);\n"
                "  setTimeout(function() { ws.close(); }, 1000);\n"
                "}\n"
                "ws.onclose = function(event)\n"
                "{\n"
                "  console.log(event);\n"
                "  console.log(\"closed\");\n"
                "  print();\n"
                "\n}";

            using namespace htmlpp;
            res
                ->content("text/html")
                ->body(
                    html(body(
                        p("Hello, World"),
                        script({{"type", "text/javascript"}}, js))))
                ->finish(req);
          });

  app.ws("/iws",
         [](const std::unique_ptr<wafflepp::WebSocket> &ws) {
           ws->checkorigin = [](const std::string &origin) {
             return origin == "http://localhost:8080";
           };

           ws->onopen = [](const std::unique_ptr<wafflepp::Request> &) {
             std::cout << "/ws/opened" << std::endl;
           };

           ws->onmessage = [&ws](const wafflepp::WebSocket::Message &data) {
             std::cout << data.data << std::endl;
             ws->write(data.data);
             ws->ping("test");
           };

           ws->onpong = [](const wafflepp::WebSocket::Message &data) {
             std::cout << data.data << std::endl;
           };

           ws->onclose = [](/*const std::unique_ptr<wafflepp::Request> &*/) {
             std::cout << "/ws/closed" << std::endl;
           };
         });

  app.listen(8080);
}
