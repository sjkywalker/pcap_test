all: pcap_test

pcap_test: main.o functions.o
	g++ -g -o pcap_test main.o functions.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

functions.o:
	g++ -g -c -o functions.o functions.cpp

clean:
	rm -f *.o
	rm -f pcap_test

