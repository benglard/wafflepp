CXXFLAGS :=-O3 -std=gnu++20
CXX=g++

http: http.cpp httpserver.h json.hpp render.hpp
	$(CXX) $(CXXFLAGS) -Wall -Wextra -Werror -I . http.cpp -o http

render: render.cpp render.hpp
	$(CXX) $(CXXFLAGS) -Wall -Wextra -Werror render.cpp -o render

clean:
	@rm http render
