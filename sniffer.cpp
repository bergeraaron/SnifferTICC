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
void setup_threads(int num_threads)
{
    if(num_threads > MaxThreads)
        num_threads = MaxThreads;
    // Setup threads
    for(int i=0;i<num_threads;i++)
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
	    //think I have a problem with the inita nd threading
//            pthread_mutex_lock(&StructMutex);
//            init(TICC_devices[*tctr].dev,TICC_devices[*tctr].channel);
//            TICC_devices[*tctr].configured = true;
//            pthread_mutex_unlock(&StructMutex);
            if(debug_output)
                printf("read\n");
            if(TICC_devices[*tctr].dev_type == CC2531)
                zigbee_read(*tctr,TICC_devices[*tctr].dev,TICC_devices[*tctr].channel);
            if(TICC_devices[*tctr].dev_type == CC2540)
                btle_read(*tctr,TICC_devices[*tctr].dev,TICC_devices[*tctr].channel);
        }
        else if(cmd_Run == false)
        {
            if(debug_output)
            printf("shut down thread :%d\n",*tctr);
            main_shutdown = true;
            break;
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
    if(debug_output){printf("pthread_mutex_lock zigbee\n");}
    pthread_mutex_lock(&ZigbeeMutex);
    pcap_dump((u_char *)z_d, &z_hdr, data);
    if(debug_output){printf("pthread_mutex_unlock zigbee\n");}
    pthread_mutex_unlock(&ZigbeeMutex);
}

void close_zigbee_pcap()
{
    if(debug_output)
        printf("close the pcap\n");

    if(z_pcap != NULL)
        pcap_close(z_pcap);
    if(z_d != NULL)
        pcap_dump_close(z_d);
}

void zigbee_read(int tctr, libusb_device_handle *dev, int channel)
{
    u_char data[1024];
    while (1)
    {
        int xfer = 0;
//        if(debug_output){printf("pthread_mutex_lock usb\n");}
//        pthread_mutex_lock(&UsbMutex);
        int ret = libusb_bulk_transfer(dev, DATA_EP_CC2531, data, sizeof(data), &xfer, TIMEOUT);
//        if(debug_output){printf("pthread_mutex_unlock usb\n");}
//        pthread_mutex_unlock(&UsbMutex);
        printf("zb ret:%d xfer:%d\n",ret,xfer);
        if (ret == 0)
        {
            if(xfer > 7)
            {
            if(debug_output)
            {
                printf("channel:%d ret:%d xfer:%d\n",channel,ret,xfer);
                for (int i = 0; i < xfer; i++)
                    printf(" %02X", data[i]);
                printf("\n");
            }
            if(debug_output){printf("pthread_mutex_lock struct\n");}
            pthread_mutex_lock(&StructMutex);
            TICC_devices[tctr].pkt_ctr++;
            if(debug_output){printf("pthread_mutex_unlock struct\n");}
            pthread_mutex_unlock(&StructMutex);

            if(save_files)
                write_zigbee_pcap(data, xfer);	

            if(cmd_Run == false)
                break;
            }
        }
        else
        {
            if(ret == LIBUSB_ERROR_IO && debug_output)
                printf("zb LIBUSB_ERROR_IO\n");
            else if(ret == LIBUSB_ERROR_INVALID_PARAM && debug_output)
                printf("zb LIBUSB_ERROR_INVALID_PARAM\n");
            else if(ret == LIBUSB_ERROR_ACCESS && debug_output)
                printf("zb LIBUSB_ERROR_ACCESS\n");
            else if(ret == LIBUSB_ERROR_NO_DEVICE && debug_output)
                printf("zb LIBUSB_ERROR_NO_DEVICE\n");
            else if(ret == LIBUSB_ERROR_NOT_FOUND && debug_output)
                printf("zb LIBUSB_ERROR_NOT_FOUND\n");
            else if(ret == LIBUSB_ERROR_BUSY && debug_output)
                printf("zb LIBUSB_ERROR_BUSY\n");
            else if(ret == LIBUSB_ERROR_TIMEOUT && debug_output)
                printf("zb LIBUSB_ERROR_TIMEOUT ctr:%d\n",TICC_devices[tctr].timeout_ctr);
            else if(ret == LIBUSB_ERROR_OVERFLOW && debug_output)
                printf("zb LIBUSB_ERROR_OVERFLOW\n");
            else if(ret == LIBUSB_ERROR_PIPE && debug_output)
                printf("zb LIBUSB_ERROR_PIPE\n");
            else if(ret == LIBUSB_ERROR_INTERRUPTED && debug_output)
                printf("zb LIBUSB_ERROR_INTERRUPTED\n");
            else if(ret == LIBUSB_ERROR_NO_MEM && debug_output)
                printf("zb LIBUSB_ERROR_NO_MEM\n");
            else if(ret == LIBUSB_ERROR_NOT_SUPPORTED && debug_output)
                printf("zb LIBUSB_ERROR_NOT_SUPPORTED\n");
            else
            {
                if(debug_output)
                    printf("zb LIBUSB_ERROR:%d\n",ret);
            }
            if(ret != LIBUSB_ERROR_TIMEOUT)
            {
                if(debug_output){printf("pthread_mutex_lock usb\n");}
                pthread_mutex_lock(&UsbMutex);
                //init(dev,channel);
                libusb_reset_device(dev);
                if(debug_output){printf("pthread_mutex_unlock usb\n");}
                pthread_mutex_unlock(&UsbMutex);
                TICC_devices[tctr].error_ctr++;
            }
            else
            {
                TICC_devices[tctr].timeout_ctr++;
                if(TICC_devices[tctr].timeout_ctr > 30)
                {
                    if(debug_output){printf("pthread_mutex_lock usb\n");}
                    pthread_mutex_lock(&UsbMutex);
                    //init(dev,channel);
                    libusb_reset_device(dev);
                    if(debug_output){printf("pthread_mutex_unlock usb\n");}
                    pthread_mutex_unlock(&UsbMutex);
                    TICC_devices[tctr].timeout_ctr=0;
                }
            }
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
    if(debug_output){printf("pthread_mutex_lock btle\n");}
    pthread_mutex_lock(&BtleMutex);
    pcap_dump((u_char *)bt_d, &bt_hdr, data);
    if(debug_output){printf("pthread_mutex_unlock btle\n");}
    pthread_mutex_unlock(&BtleMutex);
}

void close_btle_pcap()
{
    if(debug_output)
        printf("close the pcap\n");
    if(bt_pcap != NULL)
        pcap_close(bt_pcap);
    if(bt_d != NULL)
        pcap_dump_close(bt_d);
}

void btle_read(int tctr, libusb_device_handle *dev, int channel)
{
    u_char data[1024];
    while (1)
    {
        int xfer = 0;
//        if(debug_output){printf("pthread_mutex_lock usb\n");}
//        pthread_mutex_lock(&UsbMutex);
        int ret = libusb_bulk_transfer(dev, DATA_EP_CC2540, data, sizeof(data), &xfer, TIMEOUT);
//        if(debug_output){printf("pthread_mutex_unlock usb\n");}
//        pthread_mutex_unlock(&UsbMutex);
        printf("bt ret:%d xfer:%d\n",ret,xfer);
        if (ret == 0)
        {
            if(xfer > 7)
            {
            if(debug_output)
            {
                printf("channel:%d ret:%d xfer:%d\n",channel,ret,xfer);
                for (int i = 0; i < xfer; i++)
                    printf(" %02X", data[i]);
                printf("\n");
            }
            if(debug_output){printf("pthread_mutex_lock struct\n");}
            pthread_mutex_lock(&StructMutex);
            TICC_devices[tctr].pkt_ctr++;
            if(debug_output){printf("pthread_mutex_unlock struct\n");}
            pthread_mutex_unlock(&StructMutex);

            if(save_files)
                write_btle_pcap(data, xfer);

            if(cmd_Run == false)
                break;
            }
        }
        else
        {

            if(ret == LIBUSB_ERROR_IO && debug_output)
                printf("bt LIBUSB_ERROR_IO\n");
            else if(ret == LIBUSB_ERROR_INVALID_PARAM && debug_output)
                printf("bt LIBUSB_ERROR_INVALID_PARAM\n");
            else if(ret == LIBUSB_ERROR_ACCESS && debug_output)
                printf("bt LIBUSB_ERROR_ACCESS\n");
            else if(ret == LIBUSB_ERROR_NO_DEVICE && debug_output)
                printf("bt LIBUSB_ERROR_NO_DEVICE\n");
            else if(ret == LIBUSB_ERROR_NOT_FOUND && debug_output)
                printf("bt LIBUSB_ERROR_NOT_FOUND\n");
            else if(ret == LIBUSB_ERROR_BUSY && debug_output)
                printf("bt LIBUSB_ERROR_BUSY\n");
            else if(ret == LIBUSB_ERROR_TIMEOUT && debug_output)
                printf("bt LIBUSB_ERROR_TIMEOUT ctr:%d\n",TICC_devices[tctr].timeout_ctr);
            else if(ret == LIBUSB_ERROR_OVERFLOW && debug_output)
                printf("bt LIBUSB_ERROR_OVERFLOW\n");
            else if(ret == LIBUSB_ERROR_PIPE && debug_output)
                printf("bt LIBUSB_ERROR_PIPE\n");
            else if(ret == LIBUSB_ERROR_INTERRUPTED && debug_output)
                printf("bt LIBUSB_ERROR_INTERRUPTED\n");
            else if(ret == LIBUSB_ERROR_NO_MEM && debug_output)
                printf("bt LIBUSB_ERROR_NO_MEM\n");
            else if(ret == LIBUSB_ERROR_NOT_SUPPORTED && debug_output)
                printf("bt LIBUSB_ERROR_NOT_SUPPORTED\n");
            else
            {
                if(debug_output)
                    printf("bt LIBUSB_ERROR:%d\n",ret);
            }
            if(ret != LIBUSB_ERROR_TIMEOUT)
            {
                if(debug_output){printf("pthread_mutex_lock usb\n");}
                pthread_mutex_lock(&UsbMutex);
                //init(dev,channel);
                libusb_reset_device(dev);
                if(debug_output){printf("pthread_mutex_unlock usb\n");}
                pthread_mutex_unlock(&UsbMutex);
                TICC_devices[tctr].error_ctr++;
            }
            else
            {
                TICC_devices[tctr].timeout_ctr++;
                if(TICC_devices[tctr].timeout_ctr > 30)
                {
                    if(debug_output){printf("pthread_mutex_lock usb\n");}
                    pthread_mutex_lock(&UsbMutex);
                    //init(dev,channel);
                    libusb_reset_device(dev);
                    if(debug_output){printf("pthread_mutex_unlock usb\n");}
                    pthread_mutex_unlock(&UsbMutex);
                    TICC_devices[tctr].timeout_ctr=0;
                }
            }

        }
    }
}

int parse_cmd_line(int argc, char *argv[])
{
    memset(u_file_name,0x00,64);
    //if(argc <= 1)
    if(false)
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
            if(debug_output)
                printf("\nShutdown received.");
        }
        else
        { // we already sent the shutdown signal
           printf("Emergency shutdown.");
           //still try to shut stuff down
           for(int i=0;i<MaxThreads;i++)
           {
               if(TICC_devices[i].channel > 0)
               {
                    if(debug_output){printf("pthread_mutex_lock struct\n");}
                    pthread_mutex_lock(&StructMutex);
                    libusb_release_interface(TICC_devices[i].dev,i);
                    libusb_close(TICC_devices[i].dev);
                    if(debug_output){printf("pthread_mutex_unlock struct\n");}
                    pthread_mutex_unlock(&StructMutex);
               }
           }

           //close files if open
           close_zigbee_pcap();
           close_btle_pcap();

           end_ncurses();
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
    if(ncurses_display)
        init_ncurses();

    usb_lib_init();

    int zigbee = 0;
    int btle = 0;

    find_num_devices(zigbee,btle);
    if(debug_output)
        printf("num zigbee:%d btle:%d\n",zigbee,btle);

    if(zigbee == 0 && btle == 0)
    {
        for(int i=0;i<10;i++)
            print_status(i+2,1,11,i,i);

        print_running_status(cmd_Run);
        getch();			/* Wait for user input */
        end_ncurses();
        printf("No supported devices found\n");
        return 0;
    }
    if(zigbee > 0 && save_files)
        setup_zigbee_pcap();
    if(btle > 0 && save_files)
        setup_btle_pcap();

    setup_struct();

    // Setup threads
    setup_threads((zigbee+btle));

    find_devices();

    int main_ctr = 0;

    while(true)
    {
        if(main_shutdown)//this should wait to be sure the pcap closed
            break;
        if(ncurses_display)
            print_running_status(cmd_Run);
        if(main_ctr > 5 && ncurses_display)
        {
            for(int i=0;i<=(zigbee+btle);i++)
            {
                if(TICC_devices[i].channel > 0)
                {
if(debug_output){printf("pthread_mutex_lock struct\n");}
pthread_mutex_lock(&StructMutex);
                    print_status(i+2,(int)TICC_devices[i].dev_type,TICC_devices[i].channel,TICC_devices[i].pkt_ctr,TICC_devices[i].error_ctr);
if(debug_output){printf("pthread_mutex_iunlock struct\n");}
pthread_mutex_unlock(&StructMutex);
                }
            }
            main_ctr = 0;
        }
        main_ctr++;
        sleep(1);
    }
    if(debug_output)
        printf("close all of the libusb\n");
    for(int i=0;i<MaxThreads;i++)
    {
        if(TICC_devices[i].channel > 0)
        {
            if(debug_output){printf("pthread_mutex_lock struct\n");}
            pthread_mutex_lock(&StructMutex);
            libusb_release_interface(TICC_devices[i].dev,i);
            libusb_close(TICC_devices[i].dev);
            if(debug_output){printf("pthread_mutex_unlock struct\n");}
            pthread_mutex_unlock(&StructMutex);
        }
    }

    //close files if open
    if(zigbee > 0 && save_files)
        close_zigbee_pcap();
    if(btle > 0 && save_files)
        close_btle_pcap();

    if(ncurses_display)
        end_ncurses();

    //double free?
    //printf("libusb_exit\n");
    //libusb_exit(maincontext);
    return 0;
}

