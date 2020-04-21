all: file1_lab5 file2_lab5 file3_lab6

file1_lab5: zerkedim_lab5_certificate_output.cpp
	g++ zerkedim_lab5_certificate_output.cpp -lssl -lcrypto -o cert

file2_lab5: zerkedim_lab5_http_response.cpp
		g++ zerkedim_lab5_http_response.cpp -lssl -lcrypto -o httpresponse

file3_lab6: zerkedim_lab6.cpp
		g++ zerkedim_lab6.cpp -lssl -lcrypto -o clab6

run:
		./cert
		./httpresponse
		./clab6
