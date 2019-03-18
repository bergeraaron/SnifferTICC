#makefile
#needs libusb-1.0
#needs ncurses

all: sniffer

log.o: log.cpp log.h
	g++ -c log.cpp -o log.o
usb.o: usb.cpp usb.h
	g++ -c usb.cpp -o usb.o
pcap.o: pcap.cpp pcap.h
	g++ -c pcap.cpp -o pcap.o
ncurses.o: ncurses.cpp ncurses.h
	g++ -c ncurses.cpp -o ncurses.o
sniffer.o: sniffer.cpp sniffer.h
	g++ -c sniffer.cpp -o sniffer.o

sniffer: log.o usb.o pcap.o ncurses.o sniffer.o
	g++ log.o usb.o pcap.o sniffer.o ncurses.o -o sniffer -lusb-1.0 -lpcap -lpthread -lncurses

clean:
	rm -f *.o
	rm -f sniffer
