#define HTTPSERVER_IMPL
#include "wafflepp.h"
#include <csignal>

struct http_server_s *server{nullptr};

void exitHandler(int signal)
{
  std::cout << "exiting with signal " << signal << std::endl;
  free(server);
  exit(0);
}

inline int fib(int n)
{
  if (n <= 1)
    return n;
  return fib(n - 1) + fib(n - 2);
}

int main(const int argc, const char** argv)
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
            nlohmann::json j{{"key", "value"}, {"k2", "v2"}};
            res->json(j.dump())->finish(req);
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
                ->html(
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
            res->html(html(body("n = ", n)))->finish(req);
          });

  signal(SIGTERM, exitHandler);
  signal(SIGINT, exitHandler);

  int port{8000};
  if (argc > 1) {
    port = std::stoi(argv[1]);
  }
  std::cout << "Listening on port " << port << std::endl;
  app.listen(server, port);
}
