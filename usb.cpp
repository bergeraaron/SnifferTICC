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

#include "usb.h"

//zigbee 11-26
uint8_t zigbee_channels[16] = {11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26};
//just advertising channels
uint8_t btle_channels[16] = {37,38,39,37,38,39,37,38,39,37,38,39,37,38,39,37};

libusb_context *maincontext = NULL;
TICC_device TICC_devices[20];
int TICC_device_ctr = 0;

bool m_zigbee = true;
bool m_bt = true;

extern bool debug_output;
extern bool cmd_Run;
extern bool save_files;

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

int get_ident(libusb_device_handle *dev)
{
    uint8_t ident[32];
    int ret;
    if(debug_output)
        printf("libusb_control_transfer\n"); 
    ret = libusb_control_transfer(dev, DIR_IN, GET_IDENT, 0x00, 0x00, ident, sizeof(ident), TIMEOUT);
    if(debug_output)
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
        if(debug_output)
            printf("setting channel (LSB) failed!\n");
        return ret;
    }
    data = (channel >> 8) & 0xFF;
    ret = libusb_control_transfer(dev, DIR_OUT, SET_CHAN, 0x00, 0x01, &data, 1, TIMEOUT);
    if (ret < 0)
    {
        if(debug_output)
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
        if(debug_output)
            printf("Vendor:Device = %04x:%04x\n", desc.idVendor, desc.idProduct);

        if(desc.idVendor == 0x0451 && desc.idProduct == 0x16ae && m_zigbee)
        {
            if(debug_output)
            printf("found CC2531 %d\n",(int)idx);
            zigbee++;
        }
        else if(desc.idVendor == 0x11a0 && desc.idProduct == 0xeb20)
        {
            //probably won't have any of these
            if(debug_output)
            printf("found CC2530 %d\n",(int)idx);
        }
        else if(desc.idVendor == 0x0451 && desc.idProduct == 0x16b3 && m_bt)
        {
            if(debug_output)
            printf("found CC2540 %d\n",(int)idx);
            btle++;
        }
    }
    libusb_free_device_list(list, count);
    if(debug_output)
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
            if(debug_output)
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
            if(debug_output)
            printf("found CC2530 %d\n",(int)idx);
            //break;
        }
        else if(desc.idVendor == 0x0451 && desc.idProduct == 0x16b3 && m_bt)
        {
            if(debug_output)
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
        if(debug_output)
        printf("chan:%d ret:%d xfer:%d\n",channel,ret,xfer);
        if (ret == 0)
        {
            //the devices look to report a 4 byte counter/heartbeat, should use this for debugging
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
/**
                if(save_files)
                    write_zigbee_pcap(data, xfer);	
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
                printf("diff:%d\n",diff);
                if(ret == LIBUSB_ERROR_IO && debug_output)
                    printf("LIBUSB_ERROR_IO\n");
                else if(ret == LIBUSB_ERROR_INVALID_PARAM && debug_output)
                    printf("LIBUSB_ERROR_INVALID_PARAM\n");
                else if(ret == LIBUSB_ERROR_ACCESS && debug_output)
                    printf("LIBUSB_ERROR_ACCESS\n");
                else if(ret == LIBUSB_ERROR_NO_DEVICE && debug_output)
                    printf("LIBUSB_ERROR_NO_DEVICE\n");
                else if(ret == LIBUSB_ERROR_NOT_FOUND && debug_output)
                    printf("LIBUSB_ERROR_NOT_FOUND\n");
                else if(ret == LIBUSB_ERROR_BUSY && debug_output)
                    printf("LIBUSB_ERROR_BUSY\n");
                else if(ret == LIBUSB_ERROR_TIMEOUT && debug_output)
                    printf("LIBUSB_ERROR_TIMEOUT ctr:%d\n",TICC_devices[tctr].timeout_ctr);
                else if(ret == LIBUSB_ERROR_OVERFLOW && debug_output)
                    printf("LIBUSB_ERROR_OVERFLOW\n");
                else if(ret == LIBUSB_ERROR_PIPE && debug_output)
                    printf("LIBUSB_ERROR_PIPE\n");
                else if(ret == LIBUSB_ERROR_INTERRUPTED && debug_output)
                    printf("LIBUSB_ERROR_INTERRUPTED\n");
                else if(ret == LIBUSB_ERROR_NO_MEM && debug_output)
                    printf("LIBUSB_ERROR_NO_MEM\n");
                else if(ret == LIBUSB_ERROR_NOT_SUPPORTED && debug_output)
                    printf("LIBUSB_ERROR_NOT_SUPPORTED\n");
                else
                {
                    if(debug_output)
                        printf("LIBUSB_ERROR:%d\n",ret);
                }
                if(ret != LIBUSB_ERROR_TIMEOUT)
                {
                    if(debug_output){printf("pthread_mutex_lock usb\n");}
                    pthread_mutex_lock(&UsbMutex);
                    init(dev,channel);
                    //libusb_reset_device(dev);
                    if(debug_output){printf("pthread_mutex_unlock usb\n");}
                    pthread_mutex_unlock(&UsbMutex);
                    TICC_devices[tctr].error_ctr++;
                }
                else
                {
                    //TICC_devices[tctr].error_ctr++;
                    TICC_devices[tctr].timeout_ctr++;
                    if(TICC_devices[tctr].timeout_ctr > 30)
                    {
                        if(debug_output){printf("pthread_mutex_lock usb\n");}
                        pthread_mutex_lock(&UsbMutex);
                        init(dev,channel);
                        //libusb_reset_device(dev);
                        if(debug_output){printf("pthread_mutex_unlock usb\n");}
                        pthread_mutex_unlock(&UsbMutex);
                        TICC_devices[tctr].timeout_ctr=0;
                    }
                }
            }//end of diff
        }
    }
}
