#include "sniffer.h"
#include "log.h"
#include "pcap.h"

extern TICC_device TICC_devices[20];
extern int TICC_device_ctr;

extern bool m_zigbee;
extern bool m_bt;

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
                read_from_usb(*tctr,TICC_devices[*tctr].dev,TICC_devices[*tctr].channel);
            if(TICC_devices[*tctr].dev_type == CC2540)
                read_from_usb(*tctr,TICC_devices[*tctr].dev,TICC_devices[*tctr].channel);
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
            else if(strcmp(argv[we],"-df") == 0)
            {
                printf("debug output to file\n");
                debug_file = true;
            }
            else if(strcmp(argv[we],"-d") == 0)//debug mode, no ncurses
            {
                debug_output = true;
                ncurses_display = false;
            }
            else if(strcmp(argv[we],"-n") == 0)//ncurses mode, so no debug output
            {
                debug_output = false;
                ncurses_display = true;
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
           close_pcap(1);
           close_pcap(2);

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
        //for(int i=0;i<10;i++)
        //    print_status(i+2,1,11,i,i);

        //print_running_status(cmd_Run);
        //getch();			/* Wait for user input */
        //end_ncurses();
        printf("No supported devices found\n");
        return 0;
    }
    if(zigbee > 0 && save_files)
        setup_pcap(1,pipe_file);
    if(btle > 0 && save_files)
        setup_pcap(2,pipe_file);

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
        {
            print_running_status(cmd_Run);
            print_time();
        }
        if(ncurses_display)
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
        close_pcap(1);
    if(btle > 0 && save_files)
        close_pcap(2);

    if(ncurses_display)
        end_ncurses();

    //double free?
    //printf("libusb_exit\n");
    //libusb_exit(maincontext);
    return 0;
}

