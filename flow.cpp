/*
 * flow.cpp
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

 #include "flow.hpp"


 /**
  * Constructor of the exporter.
  * \param collectorAddress The ipv4 address of the collector.
  * \param port The port on which is listening the collector.
  * \param systemStartTime The system start time.
  */
 Exporter::Exporter(const char* collectorAddress, ushort port, uint32_t systemStartTime):systemStartTime(systemStartTime){
     /* Create socket */
     if ( (sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
         perror("Socket creation error");
         exit(-1);
     }
     /* Initialize address */
     memset((void *) &addr, 0, sizeof(addr));
     addr.sin_family = AF_INET;
     addr.sin_port = htons(port);
     /* Build address using inet_pton */
     if ( (inet_pton(AF_INET,collectorAddress, &addr.sin_addr)) <= 0) {
         perror("Address creation error");
         exit(-1);
     }
 }

 /**
  * Prints the flow in a file.
  * \param out The file where to print the flow.
  * \param f The flow to print.
  */
 void Exporter::printFlow(FILE* out,hashElement& f){
     struct in_addr struaddr;
     /**inet_ntoa need the address in network byte order.**/
     struaddr.s_addr=f.srcaddr;
     char* addr=inet_ntoa(struaddr);
     fprintf(out,"%s|", addr);
     struaddr.s_addr=f.dstaddr;
     addr=inet_ntoa(struaddr);
     fprintf(out,"%s|", addr);
     fprintf(out,"%d|",f.dPkts);
     fprintf(out,"%d|",f.dOctets);
     fprintf(out,"%d|",f.First.tv_sec);
     fprintf(out,"%d|",f.Last.tv_sec);
     fprintf(out,"%d|",ntohs(f.srcport));
     fprintf(out,"%d|",ntohs(f.dstport));
     fprintf(out,"%d|",f.tcp_flags);
     fprintf(out,"%d|",f.prot);
     fprintf(out,"%d|",f.tos);
     fprintf(out,"\n");
 }

 /**
  * Sends the expired flows to the collector.
  * \param q A queue of expired flows.
  * \param flowSequence The sequence number of the next record.
  * \param out A pointer to the file where to print the flows.
  */
 uint Exporter::sendToCollector(std::queue<hashElement>* q, u_int32_t flowSequence, FILE* out){
     uint size=q->size();
     if(size>MAX_FLOW_NUM)
         return -1;
     netflow5_record record;
     flow_ver5_hdr hdr;
     memset((void *) &record, 0, sizeof(record));
     hdr.version=htons(5);
     hdr.count=htons(q->size());
     timeval now;
     gettimeofday(&now,NULL);
     u_int32_t uptime=now.tv_sec*1000+now.tv_usec/1000-systemStartTime;
     hdr.sysUptime=htonl(uptime);
     hdr.unix_secs=htonl(now.tv_sec);
     hdr.unix_nsecs=htonl(now.tv_usec/1000);
     hdr.flow_sequence=htonl(flowSequence);
     hdr.engine_type=hdr.engine_id=hdr.sampling_interval=0;
     record.flowHeader=hdr;
     hashElement f;
     flow_ver5_rec fr;
     fr.src_as=fr.dst_as=fr.dst_mask=fr.src_mask=fr.input=fr.output=fr.nexthop=fr.pad1=fr.pad2=0; //TODO Add routing informations
     uint i;
     for(i=0; !q->empty(); i++){
         f=q->front();
         q->pop();
         if(out!=NULL)
             printFlow(out,f);
         fr.srcaddr=f.srcaddr;
         fr.dstaddr=f.dstaddr;
         fr.srcport=f.srcport;
         fr.dstport=f.dstport;
         fr.tos=f.tos;
         fr.tcp_flags=f.tcp_flags;
         fr.prot=f.prot;
         fr.First=htonl(f.First.tv_sec*1000+f.First.tv_usec/1000-systemStartTime);
         fr.Last=htonl(f.Last.tv_sec*1000+f.Last.tv_usec/1000-systemStartTime);
         fr.dOctets=htonl(f.dOctets);
         fr.dPkts=htonl(f.dPkts);
         record.flowRecord[i]=fr;
     }

     if (sendto(sock,&record,sizeof(record)-((MAX_FLOW_NUM-size)*sizeof(flow_ver5_rec)), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
         perror("Request error");
         return -1;
     }
     return 0;
 }

