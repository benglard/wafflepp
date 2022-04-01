CXXFLAGS :=-O3 -std=gnu++20
CXX=g++

http: http.cpp httpserver.h json.hpp htmlpp.h
	$(CXX) $(CXXFLAGS) -Wall -Wextra -Werror -I . http.cpp -o http

render: render.cpp htmlpp.h
	$(CXX) $(CXXFLAGS) -Wall -Wextra -Werror render.cpp -o render

clean:
	@rm http render
