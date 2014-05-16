/*
 * flow.hpp
 *
 * \date 14/mag/2010
 * \author Daniele De Sensi (d.desensi.software@gmail.com)
 * =========================================================================
 *  Copyright (C) 2010-2014, Daniele De Sensi (d.desensi.software@gmail.com)
 *
 *  This file is part of ffProbe.
 *
 *  ffProbe is free software: you can redistribute it and/or
 *  modify it under the terms of the Lesser GNU General Public
 *  License as published by the Free Software Foundation, either
 *  version 3 of the License, or (at your option) any later version.

 *  ffProbe is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  Lesser GNU General Public License for more details.
 *
 *  You should have received a copy of the Lesser GNU General Public
 *  License along with ffProbe.
 *  If not, see <http://www.gnu.org/licenses/>.
 *
 * =========================================================================
 *
 * Contains functions for creations and exportations of the flows.
 */

#ifndef FLOW_HPP_
#define FLOW_HPP_
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctime>
#include <queue>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>


#define MAX_FLOW_NUM 30

#define TCP_PROT_NUM 0x06
#define UDP_PROT_NUM 0x11

/**
 * Element of the hash table.
 */
struct hashElement {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t dPkts;      /* Packets sent */
  u_int32_t dOctets;    /* Octets sent */
  timeval First;        /* Time at start of flow */
  timeval Last;         /* and of last packet of the flow (when a packet is captured */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t tcp_flags;   /* Cumulative OR of tcp flags */
  u_int8_t prot;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t tos;         /* IP Type-of-Service */
  u_int32_t hashId;        /* Id in the hash table */
};


/**
 * NetFlow v5 header.
 */
struct flow_ver5_hdr {
  u_int16_t version;                 /* Current version=5*/
  u_int16_t count;                   /* The number of records in PDU. */
  u_int32_t sysUptime;               /* Current time in msecs since router booted */
  u_int32_t unix_secs;               /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;              /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;           /* Sequence number of total flows seen */
  u_int8_t engine_type;              /* Type of flow switching engine (RP,VIP,etc.)*/
  u_int8_t engine_id;                /* Slot number of the flow switching engine */
  u_int8_t sampling_interval;
};


/**
 * Netflow v5 flow.
 */
struct flow_ver5_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent */
  u_int32_t dOctets;    /* Octets sent */
  u_int32_t First;      /* SysUptime at start of flow */
  u_int32_t Last;       /* and of last packet of the flow (when a packet is captured */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t pad1;        /* pad to word boundary */
  u_int8_t tcp_flags;   /* Cumulative OR of tcp flags */
  u_int8_t prot;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t tos;         /* IP Type-of-Service */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int8_t src_mask;    /* source route's mask bits */
  u_int8_t dst_mask;    /* destination route's mask bits */
  u_int16_t pad2;       /* pad to word boundary */
};

/**
 * Netflow v5 record.
 */
struct netflow5_record {
  struct flow_ver5_hdr flowHeader;
  struct flow_ver5_rec flowRecord[MAX_FLOW_NUM];
};


/**
 * Exports the flows.
 */
class Exporter{
private:
    int sock; ///<Socket file descriptor
    struct sockaddr_in addr; ///<Address of the collector
    uint32_t systemStartTime; ///< System start time
public:

    /**
     * Constructor of the exporter.
     * \param collectorAddress The ipv4 address of the collector.
     * \param port The port on which is listening the collector.
     * \param systemStartTime The system start time.
     */
    Exporter(const char* collectorAddress, ushort port, uint32_t systemStartTime);

    /**
     * Prints the flow in a file.
     * \param out The file where to print the flow.
     * \param f The flow to print.
     */
    void printFlow(FILE* out,hashElement& f);

    /**
     * Sends the expired flows to the collector.
     * \param q A queue of expired flows.
     * \param flowSequence The sequence number of the next record.
     * \param out A pointer to the file where to print the flows.
     */
    uint sendToCollector(std::queue<hashElement>* q, u_int32_t flowSequence, FILE* out);
};


/**
 * Checks if a flow is expired.
 * \param f The flow to check.
 * \param idle Max number of seconds of inactivity.
 * \param lifeTime Max number of life's seconds of a flow.
 * \param now A pointer to the current time (if it is NULL this function returns true).
 */
inline bool isExpired(hashElement& f, int32_t idle, int32_t lifeTime, time_t* now){
    if(now==NULL) return true;
    /**If the flow idle timeout is expired.**/
    if((*now-f.Last.tv_sec)>idle)
        return true;

    /**If the flow lifetime timeout is expired.**/
    if((f.Last.tv_sec-f.First.tv_sec)>lifeTime)
        return true;

    /**If FIN or RST are arrived.**/
    if((f.tcp_flags&0x5)!=0x0)
        return true;

    return false;
}

/**
 * Fill an hashElement with the information contained in a captured packet.
 * \param pkt The captured packet.
 * \param datalinkOffset The size of a datalink header.
 */
inline void getFlow(const unsigned char* pkt, const int datalinkOffset, const uint32_t len, hashElement& f){
    iphdr* ip=(struct iphdr*) (pkt+datalinkOffset);
    f.prot=ip->protocol;
    f.tos=ip->tos;
    f.srcaddr=ip->saddr;
    f.dstaddr=ip->daddr;
    uint32_t ipHdrLen=(ip->ihl&0x0f)*4,payloadOffset;
    int transportOffset=datalinkOffset+ipHdrLen;
    uint8_t newflags=0;
    if(ip->protocol==TCP_PROT_NUM){
        tcphdr* tcp=(struct tcphdr*)(pkt+transportOffset);
        f.srcport=tcp->source;
        f.dstport=tcp->dest;
        newflags|=((tcp->res2&0x2)<<6);
        newflags|=((tcp->res2&0x1)<<7);
        newflags|=((tcp->urg&0x1)<<5);
        newflags|=((tcp->ack&0x1)<<4);
        newflags|=((tcp->psh&0x1)<<3);
        newflags|=((tcp->rst&0x1)<<2);
        newflags|=((tcp->syn&0x1)<<1);
        newflags|=(tcp->fin&0x1);
        payloadOffset=transportOffset+20;
    }else if(ip->protocol==UDP_PROT_NUM){
        udphdr* udp=(struct udphdr*)(pkt+transportOffset);
        f.srcport=udp->source;
        f.dstport=udp->dest;
        payloadOffset=transportOffset+8;
    }else{
        f.srcport=f.dstport=0;
        payloadOffset=transportOffset;
    }
    f.tcp_flags=newflags;
}

/**
 * Returns true if the flows have the same key (<Tos,Level 4 protocol, Level 4 Source Port, Level 4 Destination Port,
 * Level 3 Source Address, Level 3 Destination Address>)
 * \param f1 The first flow.
 * \param f2 The second flow.
 */
inline bool equals(const hashElement& f1, const hashElement& f2){
    return f1.srcaddr==f2.srcaddr && f1.dstaddr==f2.dstaddr && f1.srcport==f2.srcport &&
            f1.dstport==f2.dstport && f1.prot==f2.prot && f1.tos==f2.tos ;
}

#endif /* FLOW_HPP_ */
