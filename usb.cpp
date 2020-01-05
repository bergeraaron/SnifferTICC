#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <pcap.h>
#include <math.h>
#include <locale>

#include "usb.h"
#include "pcap.h"

//zigbee 11-26
uint8_t zigbee_channels[16] = {11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26};
//just advertising channels
uint8_t btle_channels[16] = {37,38,39,37,38,39,37,38,39,37,38,39,37,38,39,37};

libusb_context *maincontext = NULL;
TICC_device TICC_devices[20];
int TICC_device_ctr = 0;

bool m_zigbee = true;
bool m_bt = true;

extern bool full_debug_output;
extern bool debug_output;
extern bool cmd_Run;
extern bool save_files;
extern bool only_valid;

extern pthread_mutex_t ZigbeeMutex;
extern pthread_mutex_t BtleMutex;
extern pthread_mutex_t StructMutex;
extern pthread_mutex_t UsbMutex;

void setup_struct()
{
    for(int i=0;i<20;i++)
    {
        TICC_devices[i].dev=NULL;
        TICC_devices[i].dev_type=0;
        TICC_devices[i].channel=0;
        TICC_devices[i].pkt_ctr=0;
        TICC_devices[i].error_ctr=0;
        TICC_devices[i].timeout_ctr=0;
        TICC_devices[i].last_pkt_timestamp=0;
    }
}

int usb_lib_init()
{
    int rc = 0;
    rc = libusb_init(&maincontext);
    assert(rc == 0);
}

int init(libusb_device_handle *dev, int channel)
{
    int ret;
    int rc = 0; 
    /*Check if kenel driver attached*/
    if(full_debug_output)
        printf("Check if kernel driver attached\n");
    if(libusb_kernel_driver_active(dev, 0))
    {
        if(full_debug_output)
            printf("detach driver\n");
        rc = libusb_detach_kernel_driver(dev, 0); // detach driver
        assert(rc == 0);
    }
    if(full_debug_output)
        printf("libusb_claim_interface\n");
    rc = libusb_claim_interface(dev, 0);
    if(full_debug_output)
        printf("rc%d\n",rc);
    //assert(rc < 0);

    //set the configuration
    if(full_debug_output)
        printf("set the configuration\n");
    rc = libusb_set_configuration(dev, -1);
    assert(rc < 0);

    // read ident
    if(full_debug_output)
        printf("read ident\n");
    ret = get_ident(dev);
    if (ret < 0)
    {
        if(full_debug_output)
            printf("getting identity failed!\n");
        return ret;
    }

    // set power
    if(full_debug_output)
        printf("set power\n");
    ret = set_power(dev, 0x04, POWER_RETRIES);
    if (ret < 0)
    {
        if(full_debug_output)
            printf("setting power failed!\n");
        return ret;
    }
    /**
    // ?
    ret = libusb_control_transfer(dev, DIR_OUT, 0xC9, 0x00, 0x00, NULL, 0, TIMEOUT);
    if (ret < 0) {
    if(full_debug_output)
    printf("setting reg 0xC9 failed!\n");
    return ret;
    }
    /**/

    // set capture channel
    if(full_debug_output)
        printf("set capture channel %d\n",channel);
    ret = set_channel(dev, channel);
    if (ret < 0)
    {
        if(full_debug_output)
            printf("setting channel failed!\n");
        return ret;
    }

    // start capture?
    if(full_debug_output)
        printf("start capture?\n");
    ret = libusb_control_transfer(dev, DIR_OUT, SET_START, 0x00, 0x00, NULL, 0, TIMEOUT);

    return ret;
}

int get_ident(libusb_device_handle *dev)
{
    uint8_t ident[32];
    int ret;
    if(full_debug_output)
        printf("libusb_control_transfer\n"); 
    ret = libusb_control_transfer(dev, DIR_IN, GET_IDENT, 0x00, 0x00, ident, sizeof(ident), TIMEOUT);
    if(full_debug_output)
    {
        printf("print out\n");
        if (ret > 0)
        {
            printf("IDENT:");
            for (int i = 0; i < ret; i++)
                printf(" %02X", ident[i]);
            printf("\n");
        }
    }
    return ret;
}
int set_power(libusb_device_handle *dev, uint8_t power, int retries)
{
    int ret;

    // set power
    ret = libusb_control_transfer(dev, DIR_OUT, SET_POWER, 0x00, power, NULL, 0, TIMEOUT);

    // get power until it is the same as configured in set_power
    int i;
    for (i = 0; i < retries; i++)
    {
        uint8_t data;
        ret = libusb_control_transfer(dev, 0xC0, GET_POWER, 0x00, 0x00, &data, 1, TIMEOUT);
        if (ret < 0)
        {
            return ret;
        }
        if (data == power)
        {
            return 0;
        }
    }
    return ret;
}

int set_channel(libusb_device_handle *dev, uint8_t channel)
{
    int ret;
    uint8_t data;

    data = channel & 0xFF;
    ret = libusb_control_transfer(dev, DIR_OUT, SET_CHAN, 0x00, 0x00, &data, 1, TIMEOUT);
    if (ret < 0)
    {
        if(full_debug_output)
            printf("setting channel (LSB) failed!\n");
        return ret;
    }
    data = (channel >> 8) & 0xFF;
    ret = libusb_control_transfer(dev, DIR_OUT, SET_CHAN, 0x00, 0x01, &data, 1, TIMEOUT);
    if (ret < 0)
    {
        if(full_debug_output)
            printf("setting channel (LSB) failed!\n");
        return ret;
    }

    return ret;
}

int find_num_devices(int& zigbee,int& btle)
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

    for (size_t idx = 0; idx < count; ++idx)
    {
        device = list[idx];
        rc = libusb_get_device_descriptor(device, &desc);
        assert(rc == 0);
        if(full_debug_output)
            printf("Vendor:Device = %04x:%04x\n", desc.idVendor, desc.idProduct);

        if(desc.idVendor == 0x0451 && desc.idProduct == 0x16ae && m_zigbee)
        {
            if(debug_output || full_debug_output)
            printf("found CC2531 %d\n",(int)idx);
            zigbee++;
        }
        else if(desc.idVendor == 0x11a0 && desc.idProduct == 0xeb20)
        {
            //probably won't have any of these
            if(debug_output || full_debug_output)
            printf("found CC2530 %d\n",(int)idx);
        }
        else if(desc.idVendor == 0x0451 && desc.idProduct == 0x16b3 && m_bt)
        {
            if(debug_output || full_debug_output)
            printf("found CC2540 %d\n",(int)idx);
            btle++;
        }
    }
    libusb_free_device_list(list, count);
    if(debug_output || full_debug_output)
    printf("zigbee:%d btle:%d\n",zigbee,btle);
}

int find_devices()
{
    /**
    CC2531 idVendor=0x0451, idProduct=0x16ae
    CC2530 idVendor=0x11a0, idProduct=0xeb20
    CC2540 idVendor=0x0451, idProduct=0x16b3
    /**/

    int zb_ctr = 0;
    int bt_ctr = 0;

    libusb_device **list = NULL;

    libusb_device *device;
    libusb_device_descriptor desc = {0};

    int rc = 0;
    int ret = 0;
    ssize_t count = 0;

    count = libusb_get_device_list(maincontext, &list);
    assert(count > 0);

    for (size_t idx = 0; idx < count; ++idx)
    {
        device = list[idx];
        rc = libusb_get_device_descriptor(device, &desc);
        assert(rc == 0);
        if(debug_output)
            printf("Vendor:Device = %04x:%04x\n", desc.idVendor, desc.idProduct);

        if(desc.idVendor == 0x0451 && desc.idProduct == 0x16ae && m_zigbee)
        {
            if(debug_output || full_debug_output)
            printf("found CC2531 %d\n",(int)idx);
            //libusb_device_handle *dev;
            libusb_open(device,&TICC_devices[TICC_device_ctr].dev);
            assert(TICC_devices[TICC_device_ctr].dev != NULL);
            //set type 
            TICC_devices[TICC_device_ctr].dev_type = CC2531;
            TICC_devices[TICC_device_ctr].channel = zigbee_channels[zb_ctr];
            init(TICC_devices[TICC_device_ctr].dev,TICC_devices[TICC_device_ctr].channel);
            TICC_devices[TICC_device_ctr].configured = true;
            TICC_device_ctr++;
            zb_ctr++;
            //break;
        }
        else if(desc.idVendor == 0x11a0 && desc.idProduct == 0xeb20)
        {
            //probably won't have any of these
            if(debug_output || full_debug_output)
            printf("found CC2530 %d\n",(int)idx);
            //break;
        }
        else if(desc.idVendor == 0x0451 && desc.idProduct == 0x16b3 && m_bt)
        {
            if(debug_output || full_debug_output)
            printf("found CC2540 %d\n",(int)idx);
            //libusb_device_handle *dev;
            libusb_open(device,&TICC_devices[TICC_device_ctr].dev);
            assert(TICC_devices[TICC_device_ctr].dev != NULL);
            //set type 
            TICC_devices[TICC_device_ctr].dev_type = CC2540;
            TICC_devices[TICC_device_ctr].channel = btle_channels[bt_ctr];
            init(TICC_devices[TICC_device_ctr].dev,TICC_devices[TICC_device_ctr].channel);
            TICC_devices[TICC_device_ctr].configured = true;
            TICC_device_ctr++;
            bt_ctr++;
            //break;
        }
    }
    libusb_free_device_list(list, count);
}

int read_from_usb(int tctr, libusb_device_handle *dev, int channel)
{
    bool packet_valid = true;
    u_char data[1024];
    while (1)
    {
        int xfer = 0;
        int ret = 0;
//        if(debug_output){printf("pthread_mutex_lock usb\n");}
//        pthread_mutex_lock(&UsbMutex);
        if(TICC_devices[tctr].dev_type == 1)
            ret = libusb_bulk_transfer(dev, DATA_EP_CC2531, data, sizeof(data), &xfer, TIMEOUT);
        else
            ret = libusb_bulk_transfer(dev, DATA_EP_CC2540, data, sizeof(data), &xfer, TIMEOUT);

//        if(debug_output){printf("pthread_mutex_unlock usb\n");}
//        pthread_mutex_unlock(&UsbMutex);
        //if(debug_output)
        //printf("chan:%d ret:%d xfer:%d\n",channel,ret,xfer);
        if (ret == 0)
        {
            //the devices look to report a 4 byte counter/heartbeat, should use this for debugging
            if(xfer > 7)
            {
                if(debug_output || full_debug_output)
                {
                    printf("channel:%d ret:%d xfer:%d\n",channel,ret,xfer);
                    for (int i = 0; i < xfer; i++)
                    {
                        printf(" %02X", data[i]);
                    }

                    printf("\n");
                    if(TICC_devices[tctr].dev_type == 1)
                        packet_valid = parse_2531_packet(data, xfer);
                    else
                    {
                        packet_valid = parse_2540_packet(data, xfer);
                        if(packet_valid)
                        {
                            printf("\n");
                            for (int i = 0; i < xfer; i++)
                            {
                                if(isprint(data[i]))
                                {
                                    printf("%c", data[i], data[i]);
                                }
                            }
                            printf("\n");
                        }
                    }
                }
                if(full_debug_output){printf("pthread_mutex_lock struct\n");}
                pthread_mutex_lock(&StructMutex);
                TICC_devices[tctr].pkt_ctr++;
                if(full_debug_output){printf("pthread_mutex_unlock struct\n");}
                pthread_mutex_unlock(&StructMutex);
/**/
                if(save_files && only_valid)
                {
                    if(packet_valid)
                    {
                        if(full_debug_output){printf("pthread_mutex_lock struct\n");}
			if(TICC_devices[tctr].dev_type == 1)
			{
                                uint8_t tmp_usb_buf[1024];
                                int p_ctr=0;
                                for(int i=8;i<(xfer);i++) {
                                        tmp_usb_buf[p_ctr] = data[i];p_ctr++;
                                }
                                memset(data,0x00,1024);
                                for(int i=0;i<p_ctr;i++) {
                                        data[i] = tmp_usb_buf[i];
                                }
                                xfer = p_ctr;
			
		                u_int16_t crc = 0;
				crc = crc16_block(crc, data, (xfer-2));
				data[xfer-1] = crc >> 8;
				data[xfer-2] = crc & 0x00ff;;
			}
			else
			{
				uint8_t tmp_usb_buf[1024];
				int p_ctr=0;
				for(int i=8;i<(xfer-2);i++) {
					tmp_usb_buf[p_ctr] = data[i];p_ctr++;
				}
				memset(data,0x00,1024);
				for(int i=0;i<p_ctr;i++) {
					data[i] = tmp_usb_buf[i];
				}
				xfer = p_ctr;
			}
                        pthread_mutex_lock(&StructMutex);
                        write_pcap(TICC_devices[tctr].dev_type,data,xfer);	
                        if(full_debug_output){printf("pthread_mutex_unlock struct\n");}
                        pthread_mutex_unlock(&StructMutex);
                    }
                }
                else if(save_files && !only_valid)//save packets dont care if valid
                {

                    if(full_debug_output){printf("pthread_mutex_lock struct\n");}
                    pthread_mutex_lock(&StructMutex);
                    write_pcap(TICC_devices[tctr].dev_type,data,xfer);
                    if(full_debug_output){printf("pthread_mutex_unlock struct\n");}
                    pthread_mutex_unlock(&StructMutex);
                }
/**/
                if(cmd_Run == false)
                    break;
            }
            TICC_devices[tctr].timeout_ctr=0;
            TICC_devices[tctr].last_pkt_timestamp = time(0);
        }
        else
        {
            int diff = time(0) - TICC_devices[tctr].last_pkt_timestamp;
            if(diff > 10)
            {
                //printf("diff:%d\n",diff);
                if(ret == LIBUSB_ERROR_IO && full_debug_output)
                    printf("LIBUSB_ERROR_IO\n");
                else if(ret == LIBUSB_ERROR_INVALID_PARAM && full_debug_output)
                    printf("LIBUSB_ERROR_INVALID_PARAM\n");
                else if(ret == LIBUSB_ERROR_ACCESS && full_debug_output)
                    printf("LIBUSB_ERROR_ACCESS\n");
                else if(ret == LIBUSB_ERROR_NO_DEVICE && full_debug_output)
                    printf("LIBUSB_ERROR_NO_DEVICE\n");
                else if(ret == LIBUSB_ERROR_NOT_FOUND && full_debug_output)
                    printf("LIBUSB_ERROR_NOT_FOUND\n");
                else if(ret == LIBUSB_ERROR_BUSY && full_debug_output)
                    printf("LIBUSB_ERROR_BUSY\n");
                else if(ret == LIBUSB_ERROR_TIMEOUT && full_debug_output)
                    printf("LIBUSB_ERROR_TIMEOUT ctr:%d\n",TICC_devices[tctr].timeout_ctr);
                else if(ret == LIBUSB_ERROR_OVERFLOW && full_debug_output)
                    printf("LIBUSB_ERROR_OVERFLOW\n");
                else if(ret == LIBUSB_ERROR_PIPE && full_debug_output)
                    printf("LIBUSB_ERROR_PIPE\n");
                else if(ret == LIBUSB_ERROR_INTERRUPTED && full_debug_output)
                    printf("LIBUSB_ERROR_INTERRUPTED\n");
                else if(ret == LIBUSB_ERROR_NO_MEM && full_debug_output)
                    printf("LIBUSB_ERROR_NO_MEM\n");
                else if(ret == LIBUSB_ERROR_NOT_SUPPORTED && full_debug_output)
                    printf("LIBUSB_ERROR_NOT_SUPPORTED\n");
                else
                {
                    if(full_debug_output)
                        printf("LIBUSB_ERROR:%d\n",ret);
                }
                if(ret != LIBUSB_ERROR_TIMEOUT)
                {
                    if(full_debug_output){printf("pthread_mutex_lock usb\n");}
                    pthread_mutex_lock(&UsbMutex);
                    init(dev,channel);
                    //libusb_reset_device(dev);
                    if(full_debug_output){printf("pthread_mutex_unlock usb\n");}
                    pthread_mutex_unlock(&UsbMutex);
                    TICC_devices[tctr].error_ctr++;
                }
                else
                {
                    //TICC_devices[tctr].error_ctr++;
                    TICC_devices[tctr].timeout_ctr++;
                    if(TICC_devices[tctr].timeout_ctr > 30)
                    {
                        if(full_debug_output){printf("pthread_mutex_lock usb\n");}
                        pthread_mutex_lock(&UsbMutex);
                        init(dev,channel);
                        //libusb_reset_device(dev);
                        if(full_debug_output){printf("pthread_mutex_unlock usb\n");}
                        pthread_mutex_unlock(&UsbMutex);
                        TICC_devices[tctr].timeout_ctr=0;
                    }
                }
            }//end of diff
        }
    }
}

bool parse_2531_packet(unsigned char *data, int len)
{
     unsigned char payload[1024];memset(payload,0x00,1024);

     int pkt_len = data[1];
     if(full_debug_output)
     printf("pkt_len:%d len:%d\n",pkt_len,len);
     if(pkt_len != (len-3))
     {
        if(full_debug_output)
	    printf("packet length mismatch\n");
     }

     unsigned char header[4];
     int h_ctr=0;
     for(int i=3;i<7;i++)
     {
          header[h_ctr] = data[i];h_ctr++;
     }
     //get the paylaod
     int p_ctr=0;
     for(int i=8;i<(len-2);i++)
     {
          payload[p_ctr] = data[i];p_ctr++;
     }
     int payload_len = data[7] - 0x02;
     if(full_debug_output)
         printf("p_ctr:%d payload_len:%d\n",p_ctr,payload_len);
     if(p_ctr != payload_len)
     {
          if(full_debug_output)
              printf("payload size mismatch\n");
     }

     unsigned char fcs1 = data[len-2];
     unsigned char fcs2 = data[len-1];
     if(full_debug_output)
         printf("fcs1:%02X fcs2:%02X \n",fcs1,fcs2);

//rssi is the signed value at fcs1
     int rssi = (fcs1 + (int)pow(2,7)) % (int)pow(2,8) - (int)pow(2,7) - 73;
     if(full_debug_output)
         printf("rssi:%d\n",rssi);

     unsigned char crc_ok = fcs2 & (1 << 7);

     unsigned char corr = fcs2 & 0x7f;

     if(full_debug_output)
     {
         printf("crc_ok:%02X corr:%02X \n",crc_ok,corr);

         printf("header:%02X%02X%02X%02X\n",header[0],header[1],header[2],header[3]);
     }
     if(crc_ok > 0)
     {
          if(debug_output)
              printf("pkt valid\n");

          unsigned char plen = data[7];
          unsigned short frame_control = (data[9] << 8) + data[8];
          unsigned char seq_num = data[10];
          if(debug_output)
          {
                  printf("    frame_control:%04X\n",frame_control);
                  printf("    seq_num:%02X\n",seq_num);
          }

          //beacon packet
//          unsigned short frame_control = (data[9] << 8) + data[8];//0x8000
//	  unsigned char seq_num = data[10];
if(frame_control == 0x8000)
{
          unsigned short source_pan = (data[12] << 8) + data[11];
          unsigned short source_address = (data[14] << 8) + data[13];
          unsigned short superrf_spec = (data[16] << 8) + data[15];
          unsigned short gts_fields = (data[18] << 8) + data[17];
          if(debug_output)
          {
              printf("\n");
              printf("    BEACON FRAME\n");
              printf("    frame_control:%04X\n",frame_control);
              printf("    seq_num:%02X\n",seq_num);
              printf("    source_pan:%04X\n",source_pan);
              printf("    source_address:%04X\n",source_address);
              printf("    superrf_spec:%04X\n",superrf_spec);
              printf("    gts_fields:%04X\n",gts_fields);
              printf("\n");
          }
}
          //command packet
//          unsigned short frame_control = (data[9] << 8) + data[8];//0x8023
//          unsigned char seq_num = data[10];
else if(frame_control == 0x8023)
{
          unsigned short source_pan = (data[12] << 8) + data[11];
          unsigned short source_address = (data[14] << 8) + data[13];
          unsigned short cmd_frame_id = data[15];
          if(debug_output)
          {
              printf("\n");
              printf("    COMMAND FRAME\n");
              printf("    frame_control:%04X\n",frame_control);
              printf("    seq_num:%02X\n",seq_num);
              printf("    source_pan:%04X\n",source_pan);
              printf("    source_address:%04X\n",source_address);
              printf("    cmd_frame_id:%02X\n",cmd_frame_id);
              printf("\n");
          }
}
          //data packet
 //         unsigned char plen = data[7];
 //         unsigned short frame_control = (data[9] << 8) + data[8];//0x8841
 //         unsigned char seq_num = data[10];
else if(frame_control == 0x8841)
{ 
          unsigned short dest_pan = (data[12] << 8) + data[11];
          unsigned short dest_address = (data[14] << 8) + data[13];
          unsigned short source_address = (data[16] << 8) + data[15];
          //unsigned short mac_payload = (data[18] << 8) + data[17];//I think this can be variable.... so use plen
          unsigned short mac_payload_length = plen - 9 - 2;//length of stuff from plen to the payload minus the fcs
          if(debug_output)
          {
              printf("\n");
              printf("    DATA PACKET\n");
              printf("    plen:%02X\n",plen);
              printf("    frame_control:%04X\n",frame_control);
              printf("    seq_num:%02X\n",seq_num);
              printf("    dest_pan:%04X\n",dest_pan);
              printf("    dest_address:%04X\n",dest_address);
              printf("    source_address:%04X\n",source_address);
              //printf("    mac_payload:%04X\n",mac_payload);
              printf("    payload:");
              for(int i=0;i < mac_payload_length;i++)
                  printf("%02X",data[17+i]);
              printf("\n");
          }
}
          //simpliciTI ping packet
//          unsigned char plen = data[7];
//          unsigned short frame_control = (data[9] << 8) + data[8];//0x8841
//          unsigned char seq_num = data[10];
else if(frame_control == 0x8841)
{
          unsigned int dest_address = (data[17] << 32) + (data[16] << 16) + (data[15] << 8) + data[14];
          unsigned int source_address = (data[21] << 32) + (data[20] << 16) + (data[19] << 8) + data[18];
          unsigned char port = data[22];
          unsigned char device_info = data[23];
          unsigned char trans_id = data[24];
          unsigned short payload = (data[26] << 8) + data[25];//I think this can be variable.... so use plen
          if(debug_output)
          {
              printf("\n");
              printf("    simpliciTI ping packet\n");
              printf("    plen:%02X\n",plen);
              printf("    frame_control:%04X\n",frame_control);
              printf("    seq_num:%02X\n",seq_num);
              printf("    dest_address:%08X\n",dest_address);
              printf("    source_address:%08X\n",source_address);
              printf("    port:%02X\n",port);
              printf("    device_info:%02X\n",device_info);
              printf("    trans_id:%02X\n",trans_id);
              printf("    payload:%04X\n",payload);
              printf("\n");
          }
}


          return true;
     }
     else
          return false;
}
bool parse_2540_packet(unsigned char *data, int len)
{
     unsigned char payload[1024];memset(payload,0x00,1024);

     int pkt_len = data[1];
     if(full_debug_output)
     printf("pkt_len:%d len:%d\n",pkt_len,len);
     if(pkt_len != (len-3))
     {
        if(full_debug_output)
	    printf("packet length mismatch\n");
     }

     unsigned char header[4];
     int h_ctr=0;
     for(int i=3;i<7;i++)
     {
          header[h_ctr] = data[i];h_ctr++;
     }
     //get the paylaod
     int p_ctr=0;
     for(int i=8;i<(len-2);i++)
     {
          payload[p_ctr] = data[i];p_ctr++;
     }
     int payload_len = data[7] - 0x02;
     if(full_debug_output)
         printf("p_ctr:%d payload_len:%d\n",p_ctr,payload_len);
     if(p_ctr != payload_len)
     {
          if(full_debug_output)
              printf("payload size mismatch\n");
     }

     unsigned char fcs1 = data[len-2];
     unsigned char fcs2 = data[len-1];
     if(full_debug_output)
         printf("fcs1:%02X fcs2:%02X \n",fcs1,fcs2);

//rssi is the signed value at fcs1
     int rssi = (fcs1 + (int)pow(2,7)) % (int)pow(2,8) - (int)pow(2,7) - 73;
     if(full_debug_output)
         printf("rssi:%d\n",rssi);

     unsigned char crc_ok = fcs2 & (1 << 7);

     unsigned char chan = fcs2 & 0x7f;

     if(full_debug_output)
     {
         printf("crc_ok:%02X chan:%d \n",crc_ok,chan);
     }
     if(crc_ok > 0)
     {
          if(debug_output)
              printf("pkt valid\n");
          return true;
     }
     else
          return false;
}
u_int16_t crc16_block(u_int16_t crc, u_int8_t *data, int len) {
    int i;

    for (i = 0; i < len; i++)
        crc = (crc >> 8) ^ crctable[(crc ^ data[i]) & 0xFF];

    return crc;
}

