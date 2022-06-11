
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()
#include <time.h>

// IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8

// Checksum algo
unsigned short calculate_checksum(unsigned short *paddress, int len);

// 1. Change SOURCE_IP and DESTINATION_IP to the relevant
//     for your computer
// 2. Compile it using MSVC compiler or g++
// 3. Run it from the account with administrative permissions,
//    since opening of a raw-socket requires elevated preveledges.
//
//    On Windows, right click the exe and select "Run as administrator"
//    On Linux, run it as a root or with sudo.
//
// 4. For debugging and development, run MS Visual Studio (MSVS) as admin by
//    right-clicking at the icon of MSVS and selecting from the right-click
//    menu "Run as administrator"
//
//  Note. You can place another IP-source address that does not belong to your
//  computer (IP-spoofing), i.e. just another IP from your subnet, and the ICMP
//  still be sent, but do not expect to see ICMP_ECHO_REPLY in most such cases
//  since anti-spoofing is wide-spread.

#define SOURCE_IP "127.0.0.1"
// i.e the gateway or ping oxford university website for their ip-address
#define DESTINATION_IP "151.101.2.216"

int main()
{

    struct icmp ICMPhdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is the ping.\n";

    int datalen = strlen(data) + 1;
    clock_t t;
    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    ICMPhdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    ICMPhdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    ICMPhdr.icmp_id = 18; // hai

    // Sequence Number (16 bits): starts at 0
    ICMPhdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    ICMPhdr.icmp_cksum = 0;

    // Combine the packet
    char packet[IP_MAXPACKET];

    // Next, ICMP header
    memcpy((packet), &ICMPhdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy(packet + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum

    ((struct icmp *)packet)->icmp_cksum = calculate_checksum((unsigned short *)packet, ICMP_HDRLEN + datalen);

    //  icmp_cksum = calculate_checksum((unsigned short *) (packet, ICMP_HDRLEN + datalen);

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;

    dest_in.sin_addr.s_addr = inet_addr(DESTINATION_IP);

    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP )) == -1)
    {
        fprintf(stderr, "socket() failed with error: %d", errno);
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    // measure the time
    
    t = clock();
    /* sleep(100); */
    printf("%ld\n",t);

    // Send the packet using sendto() for sending datagrams.
    if (sendto(sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *)&dest_in, sizeof(dest_in)) == -1)
    {
        perror("The error: ");
        fprintf(stderr, "sendto() is failed with error: %d", errno);
        return -1;
    }

    printf("Ping  IP: %s, the total Data is: %d byts.\n", DESTINATION_IP, ICMP_HDRLEN + datalen);

    // receiving the pong reply
    bzero(&packet, sizeof(packet));
    socklen_t len = sizeof(dest_in);
    int size_recv = -1;
    while (size_recv < 0)
    {
        size_recv = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest_in, &len);
    }
    if (size_recv == 0)
    {
        printf("error aquired while waiting for the message\n");
    }
    else
    {
        t = clock()-t;
        float time_taken = ((float)t) / CLOCKS_PER_SEC;
        printf("It's took %f milliseconds to ping \n",time_taken );
    }

    close(sock);

    return 0;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}
