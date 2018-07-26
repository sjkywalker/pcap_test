all: pcap_test

main.o: main.cpp
	g++ -g -c -o main.o main.cpp

pcap_test: main.o
	g++ -g -o pcap_test main.o -lpcap

clean:
	rm -f *.o
	rm -f pcap_test

