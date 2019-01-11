#makefile
#needs libusb-1.0
#needs ncurses

all: sniffer

usb.o: usb.cpp usb.h
	g++ -c usb.cpp -o usb.o
ncurses.o: ncurses.cpp ncurses.h
	g++ -c ncurses.cpp -o ncurses.o
sniffer.o: sniffer.cpp sniffer.h
	g++ -c sniffer.cpp -o sniffer.o

sniffer: usb.o ncurses.o sniffer.o
	g++ usb.o sniffer.o ncurses.o -o sniffer -lusb-1.0 -lpcap -lpthread -lncurses

clean:
	rm -f *.o
	rm -f sniffer