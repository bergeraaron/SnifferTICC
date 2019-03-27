#include "pcap.h"

pcap_pkthdr hdr;
//zigbee pcap packet info
pcap_t *z_pcap;
pcap_dumper_t *z_d;
//btle pcap packet info
pcap_t *bt_pcap;
pcap_dumper_t *bt_d;

void setup_pcap(int dtype, bool pipe_file)
{
    /* open pcap context for Raw IP (DLT_RAW), see
    * http://www.tcpdump.org/linktypes.html */
    //https://wiki.wireshark.org/IEEE_802.15.4
    //https://www.wireshark.org/docs/dfref/z/zbee.nwk.html

    if(pipe_file)
    {
    char fifoname[128];memset(fifoname,0x00,128);
    if(dtype == 1)
        snprintf(fifoname,128,"/tmp/zigbee_cap");
    else if(dtype == 2)
        snprintf(fifoname,128,"/tmp/btle_cap");

    printf("make fifo\n");
    mkfifo(fifoname, 0666);

    if(dtype == 1)
    {
        FILE *ptr_zfile;
        printf("open fifo\n");
        ptr_zfile=fopen(fifoname, "wb");
        printf("pcap_open_dead\n");
        z_pcap = pcap_open_dead(195, 65565);//LINKTYPE_IEEE802_15_4_WITHFCS
        printf("pcap_dump_fopen\n");
        z_d = pcap_dump_fopen(z_pcap, ptr_zfile);
        if (z_d == NULL)
        {
            printf("error pcap_dump_fopen\n");
            return;
        }
    }
    else if(dtype == 2)
    {
        FILE *ptr_btfile;
        printf("open fifo\n");
        ptr_btfile=fopen(fifoname, "wb");
        printf("pcap_open_dead\n");
        bt_pcap = pcap_open_dead(251, 65565);//LINKTYPE_BLUETOOTH_LE_LL
        printf("pcap_dump_fopen\n");
        bt_d = pcap_dump_fopen(bt_pcap, ptr_btfile);
        if (bt_d == NULL)
        {
            printf("error pcap_dump_fopen\n");
            return;
        }
    }
    }
    else
    {
    //open file
    unsigned long int timestamp = time(0);
    char filename[128];memset(filename,0x00,128);
    if(dtype == 1)
        snprintf(filename,128,"zigbee_%lu.pcap",timestamp);
    else if(dtype == 2)
        snprintf(filename,128,"btle_%lu.pcap",timestamp);

    if(dtype == 1)
    {
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
    else if(dtype == 2)
    {
        FILE *ptr_btfile;
        ptr_btfile=fopen(filename, "wb");
        bt_pcap = pcap_open_dead(251, 65565);//LINKTYPE_BLUETOOTH_LE_LL
        bt_d = pcap_dump_fopen(bt_pcap, ptr_btfile);
        if (bt_d == NULL)
        {
            printf("error pcap_dump_fopen\n");
            return;
        }
    }
    }
}

void write_pcap(int dtype, unsigned char * data, int xfer)
{
    // prepare for writing
    timeval tp;
    gettimeofday(&tp, NULL);
    hdr.ts.tv_sec = time(0);  // sec
    hdr.ts.tv_usec = tp.tv_sec * 1000 + tp.tv_usec / 1000; // ms
    hdr.caplen = hdr.len = xfer;
    // write single IP packet
    if(dtype == 1)
        pcap_dump((u_char *)z_d, &hdr, data);
    else if(dtype == 2)
        pcap_dump((u_char *)bt_d, &hdr, data);
}

void close_pcap(int dtype)
{
    if(dtype == 1)
    {
        if(z_pcap != NULL)
            pcap_close(z_pcap);
        if(z_d != NULL)
            pcap_dump_close(z_d);
    }
    else if(dtype == 2)
    {
        if(bt_pcap != NULL)
            pcap_close(bt_pcap);
        if(bt_d != NULL)
            pcap_dump_close(bt_d);
    }
}








