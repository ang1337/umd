all:
	g++ ./src/* api_usage_example.cpp -lpthread -std=c++17 -O3 -o umd_usage_example
