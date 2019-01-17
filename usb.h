#include <libusb-1.0/libusb.h>

#define TIMEOUT 1000

#define DEFAULT_CHANNEL 0x0b // 11

#define DATA_EP_CC2531 0x83
#define DATA_EP_CC2530 0x82
#define DATA_EP_CC2540 0x83
#define DATA_TIMEOUT 2500

#define GET_IDENT 0xC0
#define SET_POWER 0xC5
#define GET_POWER 0xC6
#define SET_START 0xD0
#define SET_END   0xD1
#define SET_CHAN  0xD2 // 0x0d (idx 0) + data)0x00 (idx 1)
#define DIR_OUT   0x40
#define DIR_IN    0xC0

#define POWER_RETRIES 10

#define CC2531 0x01
#define CC2540 0x02

struct TICC_device
{
    libusb_device_handle *dev;
    uint8_t channel;
    unsigned char dev_type;
    bool configured;
    unsigned int pkt_ctr;
    unsigned int error_ctr;
    unsigned int timeout_ctr;
    unsigned int last_pkt_timestamp;
    bool active;
};

void setup_struct();
int usb_lib_init();
int init(libusb_device_handle *dev, int channel);
int get_ident(libusb_device_handle *dev);
int set_power(libusb_device_handle *dev, uint8_t power, int retries);
int set_channel(libusb_device_handle *dev, uint8_t channel);
int find_num_devices(int& zigbee,int& btle);
int find_devices();
int read_from_usb(int tctr, libusb_device_handle *dev, int channel);
