#include "sniffer.h"

extern TICC_device TICC_devices[20];
extern int TICC_device_ctr;

extern bool m_zigbee;
extern bool m_bt;

//zigbee pcap packet info
pcap_pkthdr z_hdr;
pcap_t *z_pcap;
pcap_dumper_t *z_d;
//btle pcap packet info
pcap_pkthdr bt_hdr;
pcap_t *bt_pcap;
pcap_dumper_t *bt_d;

//functions
void setup_threads()
{
    // Setup threads
    for(int i=0;i<MaxThreads;i++)
    {
        thread_number[i] = i;
        thread_running[i] = 0;//thread not being used
        sleeptimes[i] = 1;//have them sleep for 10 sec until we need them

        if(pthread_create(&workers[i], NULL,
        (void*(*)(void*))command_thread, (void*)&thread_number[i]) != 0){//(void*)0
        printf("failed on create Commander thread.");
        exit(1);
        }
    }
}

void* command_thread(void * arg)
{
    if(debug_output)
        printf("command thread \n");
    int * tctr;
    tctr = (int *) arg;
    if(debug_output)
    {
        printf("tctr:%d\n",*tctr);
        printf("detach\n");
    }
    pthread_detach(pthread_self());

    while(true)
    {
        sleep(sleeptimes[*tctr]);// sleep 2 s

        if(TICC_devices[*tctr].channel > 0 && cmd_Run == true)
        {
            if(debug_output)
                printf("init:%d dev_type:%02X\n",*tctr,TICC_devices[*tctr].dev_type);
            init(TICC_devices[*tctr].dev,TICC_devices[*tctr].channel);
            TICC_devices[*tctr].configured = true;
            if(debug_output)
                printf("read\n");
            if(TICC_devices[*tctr].dev_type == CC2531)
                zigbee_read(TICC_devices[*tctr].dev,TICC_devices[*tctr].channel);
            if(TICC_devices[*tctr].dev_type == CC2540)
                btle_read(TICC_devices[*tctr].dev,TICC_devices[*tctr].channel);
        }
        else if(cmd_Run == false)
        {
            printf("shut down thread :%d\n",*tctr);
            main_shutdown = true;
        }
    }
    if(debug_output)
    printf("exit thread\n");
    pthread_exit(NULL);
}

void setup_zigbee_pcap()
{
    /* open pcap context for Raw IP (DLT_RAW), see
    * http://www.tcpdump.org/linktypes.html */
    //https://wiki.wireshark.org/IEEE_802.15.4
    //https://www.wireshark.org/docs/dfref/z/zbee.nwk.html

    //open file
    unsigned long int timestamp = time(0);
    char filename[128];memset(filename,0x00,128);
    snprintf(filename,128,"zigbee_%lu.pcap",timestamp);
    FILE *ptr_zfile;
    ptr_zfile=fopen(filename, "wb");

    z_pcap = pcap_open_dead(195, 65565);//LINKTYPE_IEEE802_15_4_WITHFCS
    z_d = pcap_dump_fopen(z_pcap, ptr_zfile);
    if (z_d == NULL)
    {
        printf("error pcap_dump_fopen\n");
        return;
    }
}

void write_zigbee_pcap(unsigned char * data, int xfer)
{
    // prepare for writing
    timeval tp;
    gettimeofday(&tp, NULL);
    z_hdr.ts.tv_sec = time(0);  // sec
    z_hdr.ts.tv_usec = tp.tv_sec * 1000 + tp.tv_usec / 1000; // ms
    z_hdr.caplen = z_hdr.len = xfer;
    // write single IP packet
    pthread_mutex_lock(&ZigbeeMutex);
    pcap_dump((u_char *)z_d, &z_hdr, data);
    pthread_mutex_unlock(&ZigbeeMutex);
}

void close_zigbee_pcap()
{
    if(debug_output)
        printf("close the pcap\n");
    pcap_dump_close(z_d);
}

void zigbee_read(libusb_device_handle *dev, int channel)
{
    u_char data[1024];
    while (1)
    {
        int xfer = 0;
        int ret = libusb_bulk_transfer(dev, DATA_EP_CC2531, data, sizeof(data), &xfer, TIMEOUT);
        if (ret == 0 && xfer > 7)
        {
            if(debug_output)
            {
                printf("channel:%d ret:%d xfer:%d\n",channel,ret,xfer);
                for (int i = 0; i < xfer; i++)
                    printf(" %02X", data[i]);
                printf("\n");
            }

            write_zigbee_pcap(data, xfer);	

            if(cmd_Run == false)
                break;
        }
    }
}

void setup_btle_pcap()
{
    /* open pcap context for Raw IP (DLT_RAW), see
    * http://www.tcpdump.org/linktypes.html */
    //https://wiki.wireshark.org/IEEE_802.15.4
    //https://www.wireshark.org/docs/dfref/z/zbee.nwk.html

    //open file
    unsigned long int timestamp = time(0);
    char filename[128];memset(filename,0x00,128);
    snprintf(filename,128,"btle_%lu.pcap",timestamp);
    FILE *ptr_btfile;
    ptr_btfile=fopen(filename, "wb");

    //#define LINKTYPE_BLUETOOTH_LE_LL 251
    //#define LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR 256

    bt_pcap = pcap_open_dead(251, 65565);//LINKTYPE_BLUETOOTH_LE_LL
    bt_d = pcap_dump_fopen(bt_pcap, ptr_btfile);
    if (bt_d == NULL)
    {
        printf("error pcap_dump_fopen\n");
        return;
    }
}

void write_btle_pcap(unsigned char * data, int xfer)
{
    // prepare for writing
    timeval tp;
    gettimeofday(&tp, NULL);
    bt_hdr.ts.tv_sec = time(0);  // sec
    bt_hdr.ts.tv_usec = tp.tv_sec * 1000 + tp.tv_usec / 1000; // ms
    bt_hdr.caplen = bt_hdr.len = xfer;
    // write single IP packet
    pthread_mutex_lock(&BtleMutex);
    pcap_dump((u_char *)bt_d, &bt_hdr, data);
    pthread_mutex_unlock(&BtleMutex);
}

void close_btle_pcap()
{
    if(debug_output)
        printf("close the pcap\n");
    pcap_dump_close(bt_d);
}

void btle_read(libusb_device_handle *dev, int channel)
{
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

            write_btle_pcap(data, xfer);

            if(cmd_Run == false)
                break;
        }
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
        printf("\t-i zb \tignore zigbee devices\n");
        printf("\t-i bt \tignore bluetooth devices\n");
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
                //TICC_dev.channel = atoi(argv[we+1]);
            }
            else if(strcmp(argv[we],"-o") == 0)
            {
                printf("we have a output file\n");
                snprintf(u_file_name,64,"%s",argv[we+1]);
            }
            else if(strcmp(argv[we],"-d") == 0)
            {
                debug_output = true;
            }
            else if(strcmp(argv[we],"-i") == 0)//ignore something
            {
                if(strcmp(argv[we+1],"zb") == 0)//ignore zigbee
                {
                    m_zigbee = false;
                }
                else if(strcmp(argv[we+1],"bt") == 0)//ignore bluetooth
                {
                    m_bt = false;
                }
            }
        }
        return 1;
    }
}

void SigHandler(int sig)
{
    switch(sig)
    {
        case SIGHUP:
            break;
        case SIGTERM:
        case SIGINT:
        if(cmd_Run)
        {
            cmd_Run = false;
            printf("\nShutdown received.");
        }
        else
        { // we already sent the shutdown signal
            printf("Emergency shutdown.");
           exit(1);
        }
        break;
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
    parse_cmd_line(argc, argv);
    SetupSigHandler();

    usb_lib_init();

    int zigbee = 0;
    int btle = 0;

    find_num_devices(zigbee,btle);
    printf("num zigbee:%d btle:%d\n",zigbee,btle);

    if(zigbee == 0 && btle == 0)
    {
        printf("No supported devices found\n");
        return 0;
    }

    setup_zigbee_pcap();
    setup_btle_pcap();

    setup_struct();

    // Setup threads
    setup_threads();

    find_devices();

    while(true)
    {
        sleep(10);
        if(main_shutdown)//this should wait to be sure the pcap closed
            break;

        //print packet counts
        for(int i=0;i<20;i++)
        {
            if(TICC_devices[i].configured)
            {
                printf("Channel:%d PktCnt:%d\n",TICC_devices[i].channel,TICC_devices[i].pkt_ctr);
            }
        }
        printf("\n\n");
    }
    if(debug_output)
        printf("close all of the libusb\n");
    for(int i=0;i<MaxThreads;i++)
    {
        if(TICC_devices[i].channel > 0)
        {
            libusb_release_interface(TICC_devices[i].dev,i);
            libusb_close(TICC_devices[i].dev);
        }
    }

    //close files if open
    close_zigbee_pcap();
    close_btle_pcap();

    //double free?
    //printf("libusb_exit\n");
    //libusb_exit(maincontext);
    return 0;
}

