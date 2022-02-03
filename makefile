libtcp.a:

	g++ -c -I. tcp/src/*.cpp -pthread -std=c++17
	ar cr libtcp.a ./*.o
	rm -rf ./*.o

client: libtcp.a
	g++  -ggdb -O0 -DDEBUG ./client/main.cpp -I/usr/include/cryptopp -L/home/under/Музыка/TcpServer-master -o test_client  -lcryptopp -ltcp -pthread -std=c++17

server: libtcp.a
	g++ -ggdb -O0 -DDEBUG ./server/main.cpp -I/usr/include/cryptopp -L/home/under/Музыка/TcpServer-master -o test_server -lcryptopp -ltcp -pthread -std=c++17

lib: libtcp.a

all: client server

clean:
	rm -rf ./test_* ./libtcp.a ./TcpServer.pro.* ./TcpClient.pro.* *.o
