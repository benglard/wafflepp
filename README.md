# wafflepp

- Lightweight C++ web framework
- Inspired by [waffle](https://github.com/benglard/waffle) which is inspired by [express](https://expressjs.com/)
- Based on [httpserver.h](https://github.com/jeremycw/httpserver.h)

## Examples

```c++
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

  app.listen(8080);
}
```

## Features

- Express-like view functions
- URL regex parameters
- URL query arguments
- Cookies 🍪
- Redirects
- JSON parsing/responses
- Form parsing
- HTML rendering API
- Minimal error handling