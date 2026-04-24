
/* Program Name: arp_test.c
 * Author: Thai Nguyen

 * System Requirements: Compile and run on Linux systems with 'root' user privileges, or
                        CAP_NET_RAW and CAP_NET_ADMIN capabilities.

 * Purpose: This program attempts to find the MAC address of the device with the specified IP address.
            It first checks the system's ARP cache for the MAC address. If the MAC address is not
            present in the ARP table, the program will send out an ARP request packet using the (optional) device
            interface specified in the second command-line argument.
            If no interface is specified, the first found active interface will be used.
            The program will then also try to insert the new found MAC address into the system's ARP cache.

 * Usage: The program takes one required command-line argument (argv[1]) as the IP address of the device whose
          MAC address is to be found. An optional second argument can be specified as the name of the device interface
          where ARP request packets will be sent.
*/

#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <string.h>
#include <errno.h>
#include <net/if_arp.h>
#include <netinet/in.h>

#define NUM_OF_INTFC 8

#define IP_ADDR_LEN 4

#define MAC_ADDR_LEN 6

#define ARP_MSG_LEN 42

typedef struct
{
    unsigned short hwr;
    unsigned short protocol;
    unsigned char hln;
    unsigned char pln;
    unsigned short opcode;
    unsigned char sha[MAC_ADDR_LEN];
    unsigned char spa[IP_ADDR_LEN];
    unsigned char tha[MAC_ADDR_LEN];
    unsigned char tpa[IP_ADDR_LEN];
} arpHeader;

typedef struct
{
    unsigned char dest_addr[MAC_ADDR_LEN];
    unsigned char src_addr[MAC_ADDR_LEN];
    unsigned short type;
} etherHeader;

typedef struct
{
    unsigned char ip_addr[IP_ADDR_LEN];
    unsigned char mac_addr[MAC_ADDR_LEN];
    char intfc_name[IFNAMSIZ];
} intfcAddr;

/* Helper functions...*/
unsigned short ntohs_2(unsigned char bytes[], int offset)
{ /* Convert a short int from network order to little endian order. */

    unsigned int temp1 = 0, temp2 = 0;

    temp1 = bytes[offset];
    temp2 = bytes[offset + 1];

    temp1 = temp1 << 8;

    return (unsigned short)(temp1 | temp2);
}

void decodeArpReply(unsigned char *msg)
{ /* Decode ARP response packets. */

    int index = sizeof(etherHeader), count;
    unsigned short temp;

    temp = ntohs_2(msg, index);
    index += 2;

    printf("Hardware is: %d\n", temp);

    temp = ntohs_2(msg, index);
    index += 2;

    printf("Protocol is: %0x\n", temp);

    printf("Hardware Address Length: %0x\n", msg[index++]);

    printf("Protocol Address Length: %0x\n", msg[index++]);

    temp = ntohs_2(msg, index);
    index += 2;

    printf("Op code is: %d\n", temp);

    printf("Sender hardware address: ");
    for (count = 1; count <= MAC_ADDR_LEN; count++, index++)
        printf("%0x ", msg[index]);
    printf("\n");

    printf("Sender Protocol Address: ");
    for (count = 1; count <= IP_ADDR_LEN; count++, index++)
        printf("%d ", msg[index]);
    printf("\n");

    printf("Target hardware address: ");
    for (count = 1; count <= MAC_ADDR_LEN; count++, index++)
        printf("%0x ", msg[index]);
    printf("\n");

    printf("Target Protocol Address: ");
    for (count = 1; count <= IP_ADDR_LEN; count++, index++)
        printf("%d ", msg[index]);
    printf("\n");

    return;
}

int main(int argc, char **argv)
{

    unsigned int *temp;
    int fd, fd_arp, array_size;
    int index, retval, flag = 0;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    struct ifconf ifc;
    struct arpreq arpr;
    arpHeader *arp_header;
    etherHeader *ether_header;
    intfcAddr src_intfaddr, dest_intfaddr;
    char *error_msg;

    unsigned char recv_buf[ARP_MSG_LEN];
    unsigned char send_buf[ARP_MSG_LEN];

    unsigned char dest_mac[MAC_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; /* ARP broadcast request... */
    // unsigned char dest_ip[IP_ADDR_LEN] = { 192,168,1,1 };

    unsigned char *dest_ip;
    struct in_addr ip_in;
    ifc.ifc_buf = NULL;
    int ret = -1; /* Assume failure until success is achieved. */

    /* Processing command line arguments: argv[1] is target's IP address. */
    if (argc < 2)
    {
        printf("Usage: <program name> <ARP target's IP address (in dotted notation)>\n");
        return -1;
    }
    if (inet_aton(argv[1], &ip_in) == 0)
    { /* Check for a valid IP address and convert it into binary data. */
        printf("Error: invalid target's IP address...\n");
        return -1;
    }
    dest_ip = (unsigned char *)&ip_in;

    memcpy(dest_intfaddr.mac_addr, dest_mac, MAC_ADDR_LEN);
    memcpy(dest_intfaddr.ip_addr, dest_ip, IP_ADDR_LEN);
    memset(&sll, 0, sizeof(sll));
    memset(&ifr, 0, sizeof(ifr));

    fd_arp = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP)); /* (or 0x0806): Socket accepts ARP packets only. */

    if (fd_arp == -1)
    {
        printf("Error: Could not open Raw socket...\n");
        return -1;
    }

    /* Allocate buffer for SIOCGIFCONF ioctl.
       Size is enough for the first 8 active interfaces, but only eth* and wlan* Ethernet interfaces are supported for now.
    */
    ifc.ifc_len = NUM_OF_INTFC * sizeof(struct ifreq);
    ifc.ifc_buf = (char *)malloc(ifc.ifc_len);

    /* Call SIOCGIFCONF ioctl */
    if (ioctl(fd_arp, SIOCGIFCONF, &ifc) == -1)
        return -1;

    array_size = ifc.ifc_len / sizeof(struct ifreq);

    for (index = 0; index < array_size; index++)
    {
        ifr = ifc.ifc_req[index];
        printf("Interface name: %s\n", ifr.ifr_name);

        /* Check device interface's name. */
        if (argc > 2 && strcmp(ifr.ifr_name, argv[2]) != 0)
            continue;

        memcpy(src_intfaddr.ip_addr, ifr.ifr_addr.sa_data + 2, IP_ADDR_LEN); /* Get IP address of this interface. */

        if (ioctl(fd_arp, SIOCGIFFLAGS, &ifr) == -1)
            return -1; /* Get device interface flags. */
        if (ifr.ifr_flags & IFF_LOOPBACK)
            continue; /* Ignore loopback interface. */
        if (!(ifr.ifr_flags & (IFF_RUNNING | IFF_UP | IFF_DYNAMIC)))
        {
            printf("Interface %s is not active...\n", ifr.ifr_name);
            continue;
        }
        /* Only support Ethernet devices for now. */
        if (strncmp(ifr.ifr_name, "eth", 3) != 0 && strncmp(ifr.ifr_name, "wlan", 4) != 0)
            continue;

        if (ioctl(fd_arp, SIOCGIFHWADDR, &ifr) == -1)
            return -1; /* Get hardware information of this interface. */

        memcpy(src_intfaddr.mac_addr, ifr.ifr_addr.sa_data, MAC_ADDR_LEN);   /* Get MAC address of this interface. */
        memcpy(src_intfaddr.intfc_name, ifr.ifr_name, sizeof(ifr.ifr_name)); /* Get interface's name, e.g, wlan0, eth0... */

        // for (count=0; count <MAC_ADDR_LEN; count++) printf ("%0x\n", (unsigned char) ifr.ifr_hwaddr.sa_data[count]);

        if (ioctl(fd_arp, SIOCGIFINDEX, &ifr) == -1)
        {
            printf("Could not get interface index for: %s\n", ifr.ifr_name);
            continue;
        }
        else
        {
            sll.sll_family = AF_PACKET;
            sll.sll_ifindex = ifr.ifr_ifindex;
            sll.sll_protocol = htons(ETH_P_ARP);
            flag = 1;
            break; /* Found the desired active interface, so exit loop now. */
        }
    }

    if (!flag)
    {
        printf("Could not find a suitable network interface, exit now...\n");
        ret = 1; /* return error */
        goto cleanup;
    }
    /* Bind socket to this interface */
    if (bind(fd_arp, (struct sockaddr *)&sll, sizeof(sll)) == -1)
    {
        perror("Error binding raw socket to interface\n");
        ret = 1; /* return error */
        goto cleanup;
    }

    fd = socket(PF_INET, SOCK_STREAM, 0); /* Open a pf_inet socket to work with the ARP table. */

    memset(&arpr, 0, sizeof(arpr));
    memcpy(arpr.arp_pa.sa_data + 2, dest_ip, IP_ADDR_LEN);
    arpr.arp_pa.sa_family = AF_INET;
    memcpy(arpr.arp_dev, ifr.ifr_name, sizeof(ifr.ifr_name));

    ioctl(fd, SIOCGARP, &arpr);

    if (arpr.arp_flags & ATF_COM)
    {

        printf("Lookup Complete...\n"); /* Entry already exist in ARP table, just take the MAC address from arpr.arp_ha.sa_data[] */

        for (index = 0; index < MAC_ADDR_LEN; index++)
            printf("%0x ", (unsigned char)arpr.arp_ha.sa_data[index]);
        printf("\n");

        ret = 0; /* return success */
        goto cleanup;
    }

    ether_header = (etherHeader *)send_buf;
    memcpy(ether_header->dest_addr, dest_intfaddr.mac_addr, 6);
    memcpy(ether_header->src_addr, src_intfaddr.mac_addr, 6);
    ether_header->type = htons(0x0806);

    arp_header = (arpHeader *)(send_buf + sizeof(etherHeader));
    arp_header->hwr = htons(1);
    arp_header->protocol = htons(0x0800);
    arp_header->hln = MAC_ADDR_LEN;
    arp_header->pln = IP_ADDR_LEN;
    arp_header->opcode = htons(0x0001);
    memcpy(arp_header->sha, src_intfaddr.mac_addr, MAC_ADDR_LEN); // for (index=0;index<MAC_ADDR_LEN; index++) printf("%0x\n", arp_header->sha[index]);
    memcpy(arp_header->spa, src_intfaddr.ip_addr, IP_ADDR_LEN);   // for (index=0;index<IP_ADDR_LEN; index++) printf("%d\n", arp_header->spa[index]);
    memcpy(arp_header->tha, dest_intfaddr.mac_addr, MAC_ADDR_LEN);
    memcpy(arp_header->tpa, dest_intfaddr.ip_addr, IP_ADDR_LEN);

    memset(recv_buf, 0, sizeof(recv_buf));


    retval = sendto(fd_arp, send_buf, sizeof(send_buf), 0, NULL, 0);

    if (retval == -1)
    {
        printf("sendto fails, returns now...\n");
        printf("value of errno is: %d\n", errno);
        error_msg = strerror(errno);
        printf("Error desc is: %s\n", error_msg);
        goto cleanup;
    }

    // Set a 3-second timeout for recvfrom
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if (setsockopt(fd_arp, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) < 0) {
        perror("Error setting socket timeout\n");
        goto cleanup;
    }

    retval = recvfrom(fd_arp, recv_buf, sizeof(recv_buf), 0, NULL, 0);

    if (retval == -1)
    {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            printf("recvfrom timed out after 3 seconds, no ARP reply received.\n");
        } else {
            printf("recvfrom fails, returns now...\n");
        }
        printf("value of errno is: %d\n", errno);
        error_msg = strerror(errno);
        printf("Error desc is: %s\n", error_msg);
        goto cleanup;
    }

    decodeArpReply(recv_buf);

    for (index = 0; index < sizeof(recv_buf); index++)
        printf("%0x", recv_buf[index]);

    /* Attempt to add the new found MAC address to the ARP cache. */

    memset(&arpr, 0, sizeof(arpr));
    memcpy(arpr.arp_pa.sa_data + 2, dest_ip, IP_ADDR_LEN);              /* Copy ip address. */
    arpHeader *arp_hdr = (arpHeader *)(recv_buf + sizeof(etherHeader));
    memcpy(arpr.arp_ha.sa_data, arp_hdr->sha, MAC_ADDR_LEN); /* Copy mac address. */
    arpr.arp_pa.sa_family = AF_INET;
    arpr.arp_flags = ATF_PUBL;                                                      /* ATF_PUBL Flag is used to insert the entry into the ARP table. */
    memcpy(arpr.arp_dev, src_intfaddr.intfc_name, sizeof(src_intfaddr.intfc_name)); /* Copy interface name. */

    if (ioctl(fd, SIOCSARP, &arpr) == -1) /* Add to MAC table */
    {
        goto cleanup;
    }

    /* Print out some information useful for debugging. */
    if (arpr.arp_flags & ATF_PUBL)
        printf("\nPublish Entry...\n");
    for (index = 2; index < MAC_ADDR_LEN; index++)
        printf("%d ", (unsigned char)arpr.arp_pa.sa_data[index]);
    printf("\n");
    for (index = 0; index < MAC_ADDR_LEN; index++)
        printf("%0x ", (unsigned char)arpr.arp_ha.sa_data[index]);
    printf("\n");

    printf("\n\n");

    ret = 0; /* return success */
    
cleanup:
    if (ifc.ifc_buf)
        free(ifc.ifc_buf);
    if (fd_arp != -1)
        close(fd_arp);
    if (fd != -1)
        close(fd);

    return ret;
}

/* --- End of program --- */
