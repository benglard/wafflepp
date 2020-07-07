CXXFLAGS :=-O3 -std=c++14

http: http.cpp httpserver.h json.hpp
	$(CXX) $(CXXFLAGS) -Wall -Wextra -Werror -I . http.cpp -o http

clean:
	@rm http
