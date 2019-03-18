#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

void setup_pcap(int dtype);
void write_pcap(int dtype, unsigned char * data, int xfer);
void close_pcap(int dtype);







