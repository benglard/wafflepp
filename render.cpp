#include "render.hpp"

#include <iostream>

int main()
{
    using namespace htmlpp;

    const auto &test =
        html(
            head(
                title("Title")),
            body(
                p({{"style", "test"}}, "yo"),
                nbsp, amp, br(), hr(), p(),
                comment("test"), comment(),
                comment(
                    p("p" + std::to_string(1))),
                img({{"src", "https://www.google.com/images/srpr/logo11w.png"}})

                    ));

    std::cout << test << std::endl;
}
