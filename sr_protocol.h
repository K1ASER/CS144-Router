/*
 *  Copyright (c) 1998, 1999, 2000 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * sr_protocol.h
 *
 */

#ifndef SR_PROTOCOL_H
#define SR_PROTOCOL_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#include <sys/types.h>
#include <arpa/inet.h>


#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif



/* FIXME
 * ohh how lame .. how very, very lame... how can I ever go out in public
 * again?! /mc
 */

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 2
#endif

#ifndef __BYTE_ORDER
  #ifdef _CYGWIN_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _LINUX_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _SOLARIS_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
  #ifdef _DARWIN_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
#endif
#define ICMP_DATA_SIZE 28


/* Structure of a ICMP header
 */
struct sr_icmp_hdr {
  uint8_t icmp_type; /**< ICMP packet type */
  uint8_t icmp_code; /**< ICMP packet code (aka sub-type) */
  uint16_t icmp_sum; /**< ICMP checksum */
  
} __attribute__ ((packed)) ;
typedef struct sr_icmp_hdr sr_icmp_hdr_t;

/* Structure of a type3 ICMP header
 */
struct sr_icmp_t3_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  uint16_t unused;
  uint16_t next_mtu;
  uint8_t data[ICMP_DATA_SIZE];

} __attribute__ ((packed)) ;
typedef struct sr_icmp_t3_hdr sr_icmp_t3_hdr_t;

/**
 * @brief Structure of Type 0 (Echo reply) and Type 8 (Echo request) ICMP packets. 
 */
typedef struct __attribute__((packed))
{  
   uint8_t icmp_type; /**< ICMP Type @see sr_icmp_type */
   uint8_t icmp_code; /**< ICMP Code (should be 0 for these) */
   uint16_t icmp_sum; /**< ICMP checksum (covers entire payload) */
   uint16_t ident; /**< Echo request/reply identification number */
   uint16_t seq_num; /**< Echo request/reply sequence number */
   uint8_t data[1]; /**< Variable length data sent with request/reply */
} sr_icmp_t0_hdr_t, sr_icmp_t8_hdr_t;

/**
 * @brief Header structure for a Type 11 (Time Exceeded) ICMP packet.
 * @see http://www.ietf.org/rfc/rfc0792.txt
 */
typedef struct __attribute__((packed))
{  
   uint8_t icmp_type; /**< ICMP Type (should be 11) */
   uint8_t icmp_code; /**< ICMP Code */
   uint16_t icmp_sum; /**< ICMP checksum (covers entire payload) */
   uint16_t unused; /**< unused */
   uint8_t data[1]; /**< Variable length data containing IP datagram and first 8 bytes of transport. */
} sr_icmp_t11_hdr_t;


/*
 * Structure of an internet header, naked of options.
 */
#define IP_ADDR_LEN  (4)
struct sr_ip_hdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		/* header length */
    unsigned int ip_v:4;		/* version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		/* version */
    unsigned int ip_hl:4;		/* header length */
#else
#error "Byte ordering not specified " 
#endif 
    uint8_t ip_tos;			/* type of service */
    uint16_t ip_len;			/* total length */
    uint16_t ip_id;			/* identification */
    uint16_t ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    uint16_t ip_sum;			/* checksum */
    uint32_t ip_src, ip_dst;	/* source and dest address */
  } __attribute__ ((packed)) ;
typedef struct sr_ip_hdr sr_ip_hdr_t;

/* 
 *  Ethernet packet header prototype.  Too many O/S's define this differently.
 *  Easy enough to solve that and define it here.
 */
struct sr_ethernet_hdr
{
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
    uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
    uint16_t ether_type;                     /* packet type ID */
} __attribute__ ((packed)) ;
typedef struct sr_ethernet_hdr sr_ethernet_hdr_t;

/** 
 * @brief IP protocol header values as defined by IANA 
 * @see http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
 */
enum sr_ip_protocol {
  ip_protocol_icmp = 1,
  ip_protocol_tcp = 6,
  ip_protocol_udp = 17
};

enum sr_ethertype {
  ethertype_arp = 0x0806,
  ethertype_ip = 0x0800,
};


enum sr_arp_opcode {
  arp_op_request = 0x0001,
  arp_op_reply = 0x0002,
};

enum sr_arp_hrd_fmt {
  arp_hrd_ethernet = 0x0001,
};

enum sr_icmp_type {
   icmp_type_echo_reply = 0,
   icmp_type_desination_unreachable = 3,
   icmp_type_echo_request = 8,
   icmp_type_time_exceeded = 11
};
typedef enum sr_icmp_type sr_icmp_type_t;

enum sr_icmp_dest_unreach_code {
   icmp_code_network_unreachable = 0,
   icmp_code_destination_host_unreachable = 1,
   icmp_code_destination_port_unreachable = 3
};
typedef enum sr_icmp_type sr_icmp_code_t;


struct sr_arp_hdr
{
   uint16_t ar_hrd; /* format of hardware address   */
   uint16_t ar_pro; /* format of protocol address   */
   uint8_t ar_hln; /* length of hardware address   */
   uint8_t ar_pln; /* length of protocol address   */
   uint16_t ar_op; /* ARP opcode (command)         */
   uint8_t ar_sha[ETHER_ADDR_LEN]; /* sender hardware address      */
   uint32_t ar_sip; /* sender IP address            */
   uint8_t ar_tha[ETHER_ADDR_LEN]; /* target hardware address      */
   uint32_t ar_tip; /* target IP address            */
} __attribute__ ((packed)) ;
typedef struct sr_arp_hdr sr_arp_hdr_t;

#define TCP_OFFSET_M (0xF000)
/** @brief Urgent Pointer field significant */
#define TCP_URG_M    (0x0020)
/** @brief Acknowledgment field significant */
#define TCP_ACK_M    (0x0010)
/** @brief Push Function */
#define TCP_PSH_M    (0x0008)
/** @brief Reset the connection */
#define TCP_RST_M    (0x0004)
/** @brief Synchronize sequence numbers */
#define TCP_SYN_M    (0x0002)
/** @brief No more data from sender */
#define TCP_FIN_M    (0x0001)

/**
 * @brief Header structure for a transmission control protocol (TCP) packet header.
 * @note controlBits field should not be accessed directly, but used with associated bit masks.
 * @see http://tools.ietf.org/html/rfc793#section-3.1
 */
typedef struct __attribute__((packed))
{
   uint16_t sourcePort; /**< The source port number. */
   uint16_t destinationPort; /**< The destination port number. */
   uint32_t sequenceNumber; /**< The sequence number of the first data octet in this segment (except when SYN is present) */
   uint32_t acknowledgmentNumber; /**< Field contains the value of the next sequence number the sender of the segment is expecting to receive */
   uint16_t offset_controlBits;
   uint16_t window; /**< The number of data octets beginning with the one indicated in the acknowledgment field which the sender of this segment is willing to accept. */
   uint16_t checksum;
   uint16_t urgentPointer; /**< current value of the urgent pointer as a positive offset from the sequence number in this segment. */
} sr_tcp_hdr_t;

typedef struct __attribute__((packed))
{
   uint32_t sourceAddress; /**< The source address of the IP datagram */
   uint32_t destinationAddress; /**< The destination address of the IP datagram */
   uint8_t zeros; /**< A byte of 0 */
   uint8_t protocol; /**< IP Protocol field (should be ip_protocol_tcp) */
   uint16_t tcpLength; /**< Length of the TCP packet */
} sr_tcp_ip_pseudo_hdr_t;

/**
 * @brief Header structure for a user datagram protocol (UDP) packet header.
 * @see http://tools.ietf.org/html/rfc768
 */
typedef struct __attribute__((packed))
{
   uint16_t sourcePort;
   uint16_t destinationPort;
   uint16_t length;
   uint16_t checksum;
} sr_udp_hdr_t;

#define sr_IFACE_NAMELEN 32

#endif /* -- SR_PROTOCOL_H -- */
