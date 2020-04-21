all: file1 file2

file1: zerkedim_lab5_certificate_output.cpp
	g++ zerkedim_lab5_certificate_output.cpp -lssl -lcrypto -o cert

file2: zerkedim_lab5_http_response.cpp
		g++ zerkedim_lab5_http_response.cpp -lssl -lcrypto -o httpresponse


run:
		./cert
		./httpresponse
