#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <libusb-1.0/libusb.h>
#include <pcap.h>

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
	u_char dev_type;
	bool configured;
};
TICC_device TICC_dev;
int TICC_device_ctr = 0;

char u_file_name[64];

bool debug_output = false;

//zigbee 11-26
uint8_t zigbee_channels[16] = {11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26};
//just advertising channels
uint8_t btle_channels[16] = {37,38,39,37,38,39,37,38,39,37,38,39,37,38,39,37};

libusb_context *maincontext = NULL;

bool cmd_Run = true;

//function definitions
static int get_ident(libusb_device_handle *dev);
static int set_power(libusb_device_handle *dev, uint8_t power, int retries);
static int set_channel(libusb_device_handle *dev, uint8_t channel);
static int init(libusb_device_handle *dev, int channel);
static void zigbee_read(libusb_device_handle *dev, int channel);
static void btle_read(libusb_device_handle *dev, int channel);
int find_devices();
void SigHandler(int sig);
void SetupSigHandler();

static int get_ident(libusb_device_handle *dev)
{
    uint8_t ident[32];
    int ret;
    if(debug_output)
        printf("libusb_control_transfer\n"); 
    ret = libusb_control_transfer(dev, DIR_IN, GET_IDENT, 0x00, 0x00, ident, sizeof(ident), TIMEOUT);
    if(debug_output)
        printf("print out\n");
    if(debug_output)
        if (ret > 0) {
            int i;
            printf("IDENT:");
            for (i = 0; i < ret; i++) {
                printf(" %02X", ident[i]);
            }
            printf("\n");
        }
    return ret;
}

static int set_power(libusb_device_handle *dev, uint8_t power, int retries)
{
    int ret;

   // set power
    ret = libusb_control_transfer(dev, DIR_OUT, SET_POWER, 0x00, power, NULL, 0, TIMEOUT);
    
    // get power until it is the same as configured in set_power
    int i;
    for (i = 0; i < retries; i++) {
        uint8_t data;
        ret = libusb_control_transfer(dev, 0xC0, GET_POWER, 0x00, 0x00, &data, 1, TIMEOUT);
        if (ret < 0) {
            return ret;
        }
        if (data == power) {
            return 0;
        }
    }
    return ret;
}

static int set_channel(libusb_device_handle *dev, uint8_t channel)
{
    int ret;
    uint8_t data;

    data = channel & 0xFF;
    ret = libusb_control_transfer(dev, DIR_OUT, SET_CHAN, 0x00, 0x00, &data, 1, TIMEOUT);
    if (ret < 0) {
        if(debug_output)
            printf("setting channel (LSB) failed!\n");
        return ret;
    }
    data = (channel >> 8) & 0xFF;
    ret = libusb_control_transfer(dev, DIR_OUT, SET_CHAN, 0x00, 0x01, &data, 1, TIMEOUT);
    if (ret < 0) {
        if(debug_output)
            printf("setting channel (LSB) failed!\n");
        return ret;
    }

    return ret;
}

static int init(libusb_device_handle *dev, int channel)
{
    int ret;
    int rc = 0; 
    /*Check if kenel driver attached*/
    if(debug_output)
        printf("Check if kernel driver attached\n");
    if(libusb_kernel_driver_active(dev, 0))
    {
        if(debug_output)
            printf("detach driver\n");
        rc = libusb_detach_kernel_driver(dev, 0); // detach driver
        assert(rc == 0);
    }
    if(debug_output)
        printf("libusb_claim_interface\n");
    rc = libusb_claim_interface(dev, 0);
    if(debug_output)
        printf("rc%d\n",rc);
    //assert(rc < 0);

    //set the configuration
    if(debug_output)
        printf("set the configuration\n");
    rc = libusb_set_configuration(dev, -1);
    assert(rc < 0);

    // read ident
    if(debug_output)
        printf("read ident\n");
    ret = get_ident(dev);
    if (ret < 0)
    {
        if(debug_output)
            printf("getting identity failed!\n");
        return ret;
    }

    // set power
    if(debug_output)
        printf("set power\n");
    ret = set_power(dev, 0x04, POWER_RETRIES);
    if (ret < 0)
    {
        if(debug_output)
            printf("setting power failed!\n");
        return ret;
    }
    /**
    // ?
    ret = libusb_control_transfer(dev, DIR_OUT, 0xC9, 0x00, 0x00, NULL, 0, TIMEOUT);
    if (ret < 0) {
    if(debug_output)
    printf("setting reg 0xC9 failed!\n");
    return ret;
    }
    /**/

    // set capture channel
    if(debug_output)
        printf("set capture channel %d\n",channel);
    ret = set_channel(dev, channel);
    if (ret < 0)
    {
        if(debug_output)
            printf("setting channel failed!\n");
        return ret;
    }

    // start capture?
    if(debug_output)
        printf("start capture?\n");
    ret = libusb_control_transfer(dev, DIR_OUT, SET_START, 0x00, 0x00, NULL, 0, TIMEOUT);

    return ret;
}

static void zigbee_read(libusb_device_handle *dev, int channel)
{
	pcap_pkthdr hdr;
	timeval tp;

	char filename[128];memset(filename,0x00,128);
    if(sizeof(u_file_name) > 0)
        snprintf(filename,128,"%s.pcap",u_file_name);
    else
	    snprintf(filename,128,"zigbee_c%d.pcap",channel);
	
	FILE *ptr_myfile;
	ptr_myfile=fopen(filename, "wb");

    pcap_t *pcap;
    /* open pcap context for Raw IP (DLT_RAW), see
     * http://www.tcpdump.org/linktypes.html */
    //https://wiki.wireshark.org/IEEE_802.15.4
    //https://www.wireshark.org/docs/dfref/z/zbee.nwk.html
	#define LINKTYPE_IEEE802_15_4_WITHFCS 195
    pcap = pcap_open_dead(LINKTYPE_IEEE802_15_4_WITHFCS, 65565);
    pcap_dumper_t *d;
    d = pcap_dump_fopen(pcap, ptr_myfile);
    if (d == NULL) {
        //pcap_perror(pcap, "pcap_dump_fopen");
        printf("error pcap_dump_fopen\n");
        return;
    }

	int ctr=0;

    u_char data[1024];
    while (1)
    {
        int xfer = 0;
        int ret = libusb_bulk_transfer(dev, DATA_EP_CC2531, data, sizeof(data), &xfer, TIMEOUT);
        if (ret == 0 && xfer > 7)
        {
            if(debug_output)
            {
                printf("ret:%d xfer:%d\n",ret,xfer);
                for (int i = 0; i < xfer; i++)
                    printf(" %02X", data[i]);
                printf("\n");
            }

			// prepare for writing
			gettimeofday(&tp, NULL);
			hdr.ts.tv_sec = time(0);  // sec
			hdr.ts.tv_usec = tp.tv_sec * 1000 + tp.tv_usec / 1000; // ms
			hdr.caplen = hdr.len = xfer;

			// write single IP packet
			pcap_dump((u_char *)d, &hdr, data);

//            ctr++;
//            if(ctr == 10)
//				break;
        }
    }
    // finish up
    pcap_dump_close(d);
}

static void btle_read(libusb_device_handle *dev, int channel)
{
/**/
	pcap_pkthdr hdr;
	timeval tp;

    unsigned long int timestamp = time(0);
	char filename[128];memset(filename,0x00,128);
    if(sizeof(u_file_name) > 0)
        snprintf(filename,128,"%s.pcap",u_file_name);
    else
	    snprintf(filename,128,"btle_c%d_%lu.pcap",channel,timestamp);

	FILE *ptr_myfile;
	ptr_myfile=fopen(filename, "wb");

    pcap_t *pcap;
/**/
    /* open pcap context for Raw IP (DLT_RAW), see
     * http://www.tcpdump.org/linktypes.html */
    //https://wiki.wireshark.org/IEEE_802.15.4
    //https://www.wireshark.org/docs/dfref/z/zbee.nwk.html
/**/
	#define LINKTYPE_BLUETOOTH_LE_LL 251
	#define LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR 256
    pcap = pcap_open_dead(LINKTYPE_BLUETOOTH_LE_LL, 65565);
    pcap_dumper_t *d;
    d = pcap_dump_fopen(pcap, ptr_myfile);
    if (d == NULL) {
        //pcap_perror(pcap, "pcap_dump_fopen");
        printf("error pcap_dump_fopen\n");
        return;
    }
/**/
	int ctr=0;

    u_char data[1024];
    while (1)
    {
        int xfer = 0;
        int ret = libusb_bulk_transfer(dev, DATA_EP_CC2540, data, sizeof(data), &xfer, TIMEOUT);
        if (ret == 0 && xfer > 7)
        {
            if(debug_output)
            {
                printf("ret:%d xfer:%d\n",ret,xfer);
                for (int i = 0; i < xfer; i++)
                    printf(" %02X", data[i]);
                printf("\n");
            }

			// prepare for writing
			gettimeofday(&tp, NULL);
			hdr.ts.tv_sec = time(0);  // sec
			hdr.ts.tv_usec = tp.tv_sec * 1000 + tp.tv_usec / 1000; // ms
			hdr.caplen = hdr.len = xfer;

			// write single IP packet
			pcap_dump((u_char *)d, &hdr, data);

            if(cmd_Run == false)
			    break;
        }
    }

    // finish up
    pcap_dump_close(d);

}

int find_devices()
{

/**
CC2531 idVendor=0x0451, idProduct=0x16ae
CC2530 idVendor=0x11a0, idProduct=0xeb20
CC2540 idVendor=0x0451, idProduct=0x16b3
/**/

    libusb_device **list = NULL;
    
    libusb_device *device;
    libusb_device_descriptor desc = {0};

    int rc = 0;
    int ret = 0;
    ssize_t count = 0;


    count = libusb_get_device_list(maincontext, &list);
    assert(count > 0);

    for (size_t idx = 0; idx < count; ++idx) {
        device = list[idx];
        rc = libusb_get_device_descriptor(device, &desc);
        assert(rc == 0);
        if(debug_output)
            printf("Vendor:Device = %04x:%04x\n", desc.idVendor, desc.idProduct);

		if(desc.idVendor == 0x0451 && desc.idProduct == 0x16ae)
		{
			printf("found CC2531 %d\n",(int)idx);
			//libusb_device_handle *dev;
			libusb_open(device,&TICC_dev.dev);
			assert(TICC_dev.dev != NULL);
			//set type 
			TICC_dev.dev_type = CC2531;
			TICC_dev.channel = zigbee_channels[TICC_device_ctr];
			//break;
		}
		else if(desc.idVendor == 0x11a0 && desc.idProduct == 0xeb20)
		{
			//probably won't have any of these
			printf("found CC2530 %d\n",(int)idx);
			//break;
		}
		else if(desc.idVendor == 0x0451 && desc.idProduct == 0x16b3)
		{
			printf("found CC2540 %d\n",(int)idx);
			//libusb_device_handle *dev;
			libusb_open(device,&TICC_dev.dev);
			assert(TICC_dev.dev != NULL);
			//set type 
			TICC_dev.dev_type = CC2540;
			TICC_dev.channel = btle_channels[TICC_device_ctr];
			//break;
		}
    }
    libusb_free_device_list(list, count);
}

void SigHandler(int sig)
{
  switch(sig) {
    case SIGHUP:
      break;
    case SIGTERM:
    case SIGINT:
      if(cmd_Run) {
        cmd_Run = false;
        printf("\nShutdown received.");
      } else { // we already sent the shutdown signal

        printf("Emergency shutdown.");
        exit(1);
      }
      break;
  }
}

int parse_cmd_line(int argc, char *argv[])
{
    memset(u_file_name,0x00,64);
    if(argc <= 1)
    {
        printf("Usage:\n ./sniffer <options>\n");
        printf("\t-----OPTIONS-----\n");
        printf("\t-c\tchannel\n");
        printf("\t-o\toutput file\n");
        printf("\t-d\tdebug output\n");
        return 0;
    }
    else
    {
        for(int we=0;we < argc; we++)
        {
            printf("%d %s\n",we,argv[we]);
            if(strcmp(argv[we],"-c") == 0)
            {
                printf("we have a channel\n");
                TICC_dev.channel = atoi(argv[we+1]);
            }
            if(strcmp(argv[we],"-o") == 0)
            {
                printf("we have a output file\n");
                snprintf(u_file_name,64,"%s",argv[we+1]);
            }
            if(strcmp(argv[we],"-d") == 0)
            {
                debug_output = true;
            }
        }
        return 1;
    }
}

void SetupSigHandler()
{
  signal(SIGCHLD, SIG_IGN);  // ignore child
  signal(SIGTSTP, SIG_IGN);  // ignore tty signals
  signal(SIGTTOU, SIG_IGN);  // ignore background write attempts
  signal(SIGTTIN, SIG_IGN);  // ignore background read attempts
  signal(SIGHUP,  SigHandler);
  signal(SIGTERM, SigHandler);
  signal(SIGINT,  SigHandler);
}

int main(int argc, char *argv[])
{
    if(parse_cmd_line(argc,argv) == 0)
        return 0;

	SetupSigHandler();

	TICC_dev.dev=NULL;
	TICC_dev.dev_type=0;
	TICC_dev.channel=0;

    int rc = 0;
    rc = libusb_init(&maincontext);
    assert(rc == 0);

	find_devices();

	while(true)
	{
		sleep(10);
	}

    libusb_exit(maincontext);
	return 0;
}

