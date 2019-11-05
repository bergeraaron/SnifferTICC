#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
//#include <libusb-1.0/libusb.h>
#include <pcap.h>
#include "usb.h"
#include "ncurses.h"

//thread stuff
#define MaxThreads 20

pthread_t workers[MaxThreads];
unsigned short sleeptimes[MaxThreads];
int thread_running[MaxThreads];
int thread_number[MaxThreads];
//mutexes one for the zigbee file and one for the btle file
pthread_mutex_t ZigbeeMutex;
pthread_mutex_t BtleMutex;
pthread_mutex_t StructMutex;
pthread_mutex_t UsbMutex;

char u_file_name[64];
bool debug_output = false;
bool full_debug_output = false;
bool ncurses_display = true;
bool save_files = true;
bool pipe_file = false;
bool debug_file = false;
bool only_valid = true;

bool cmd_Run = true;
bool main_shutdown = false;

//function definitions
void setup_threads(int num_threads);
void* command_thread(void * arg);
int get_ident(libusb_device_handle *dev);
int set_power(libusb_device_handle *dev, uint8_t power, int retries);
int set_channel(libusb_device_handle *dev, uint8_t channel);
int init(libusb_device_handle *dev, int channel);
int parse_cmd_line(int argc, char *argv[]);
void setup_zigbee_pcap();
void write_zigbee_pcap(unsigned char * data, int xfer);
void close_zigbee_pcap();
void zigbee_read(int tctr, libusb_device_handle *dev, int channel);
void setup_btle_pcap();
void btle_read(int tctr, libusb_device_handle *dev, int channel);
void write_btle_pcap(unsigned char * data, int xfer);
void close_btle_pcap();
int find_devices();
int find_num_devices(int& zigbee,int& btle);
void SigHandler(int sig);
void SetupSigHandler();
