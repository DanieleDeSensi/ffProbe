/*
 * workers.hpp
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
 * This file contains the definitions of the fastflow's workers.
 */

#include "workers.hpp"

uint hsize, ///<Size of the hash table
  lhsize, ///<Size of the hash table of a SINGLE worker
  datalinkOffset, ///<Length of the datalink header
  numReaders;
bool quit; ///< Flag for the termination of the probe
long padding1[64-sizeof(bool)];
pfring** handle; ///< Pcap handle
u_int *plast;
time_t last_time = 0;
float total_rate = 0;

/**
 * The function called by pcap_dispatch when a packet arrive.
 * \param user A param passed by the worker.
 * \param phdr The header of the packet.
 * \param pdata The packet.
 */
void dispatchCallback(const struct pfring_pkthdr *phdr, const u_char *pdata , const u_char *user_bytes){
  Task* t=(Task*) user_bytes;
  hashElement f;
  /**
   * Uncomment this if you want to extract the informations
   * directly from the packet instead of using the extended header provided
   * by pfring.
   */
  getFlow(pdata,datalinkOffset,phdr->len,f);
  f.dOctets=phdr->len-datalinkOffset;
  f.First.tv_sec=t->getTimestamp();
  //gettimeofday((struct timeval*)&(f.First), NULL);
  //f.First.tv_sec=phdr->extended_hdr.timestamp_ns/1000000000;
  /**Update information using the extended header of pfring.**/
  /**        f.prot=phdr->extended_hdr.parsed_pkt.l3_proto;
        f.tos=phdr->extended_hdr.parsed_pkt.ipv4_tos;
        f.srcaddr=phdr->extended_hdr.parsed_pkt.ipv4_src;
        f.dstaddr=phdr->extended_hdr.parsed_pkt.ipv4_dst;
    f.srcport=phdr->extended_hdr.parsed_pkt.l4_src_port;
    f.dstport=phdr->extended_hdr.parsed_pkt.l4_dst_port;
        f.tcp_flags=phdr->extended_hdr.parsed_pkt.tcp.flags;;
  **/
  uint hashValue=hashFun(f,hsize);
  f.hashId=hashValue;
  t->setFlowToAdd(f,hashValue/lhsize);
}

/**
 * Signal handler for SIGINT.
 */
inline void handler(int i){
  if(quit) return;
  if(i==SIGINT){
    printf("SIGINT Received. The probe will end at the arrive of a packet or at the expiration of readTimeout.\n");
    quit=true;
  }else{
    time_t now = time(NULL);
    float partial_rate,perc=0;
    total_rate=0;
    pfring_stat ps;
    for(uint i=0; i<numReaders; i++){
      pfring_stats(handle[i], &ps);
      std::cout << "===============Reader " << i << "==============" << std::endl;
      std::cout << "Packets received: " << ps.recv << std::endl;
      std::cout << "Packets dropped: " << ps.drop << std::endl;
      partial_rate=(float)(ps.recv-plast[i])/(now-last_time);
      std::cout << "Packets Rate: " << partial_rate << std::endl;
      total_rate+=partial_rate;
      if(ps.recv!=0)
	perc=((float)ps.drop/(float)(ps.drop+ps.recv))*100;
      std::cout << "[" << perc << "% packet loss]" << std::endl;
      plast[i] = ps.recv;
    }
#ifdef MULTIPLE_READERS
    std::cout << "================Total================" << std::endl;
    std::cout << "Packets Rate: " << total_rate << std::endl;
#endif
    last_time = now;
    alarm(5);
  }
}


/**
 * Constructor of the first stage.
 * \param nw Number of workers.
 * \param device Name of the device (or of the .pcap file)
 * \param promisc 1 if the interface must be set in promiscous mode, 0 otherwise.
 * \param cnt Maximum number of packet to read from the device (or from the .pcap file).
 * \param h Size of the hash table (Sizeof(HashOfWorker1)+Sizeof(HashOfWorker2)+...+Sizeof(HashOfWorkerN)).
 * \param id The identifier of the reader.
 * \param core The id of the core on which this thread should be mapped.
 */
firstStage::firstStage(int nw, char* device, uint promisc, int cnt, int h, uint id, uint core):id(id),core(core),end(false){
#ifdef COMPUTE_STATS
    invocations=total_time=0;
    avg_latency=0;
#endif
    if(cnt==-1) maxP=std::numeric_limits<uint>::max();
    else maxP=cnt;
    nWorkers=nw!=0?nw:1;
    quit=false;
    hsize=h;
    lhsize=h/nWorkers;
    offline=false;
    handle[id]=pfring_open(device, promisc, 200);
    assert(handle[id]);
    int datalinkType=1;
    //TODO Add other switch-case to add the support to other datalink's protocols.
    switch(datalinkType){
        case 1:
            datalinkOffset=14;
            break;
        default:
            fprintf(stderr, "Datalink offset for datalink type: %d unknown.",datalinkType);
            exit(-1);
    }
    private_handle=handle[id];
    assert(pfring_set_cluster(private_handle, id+1, cluster_per_flow)==0);
    assert(pfring_set_direction(private_handle, rx_only_direction)==0);
    //pfring_set_poll_watermark(private_handle, 0);
    assert(pfring_enable_ring(private_handle)==0);
}

/**
 * Destructor of the first stage.
 */
firstStage::~firstStage(){
    pfring_close(private_handle);
}

void firstStage::core_mapping(){
    ff_mapThreadToCpu(core,-20);
}

int firstStage::svc_init(){
    core_mapping();
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set,SIGALRM);
    if(id==0){
        /**Unblocks SIGINT.**/
        sigset_t set2;
        sigemptyset(&set2);
        sigaddset(&set2,SIGINT);
        pthread_sigmask(SIG_UNBLOCK,&set2,NULL);
        /**
         * Signal handling.
         */
        struct sigaction s;
        bzero( &s, sizeof(s) );
        s.sa_handler=handler;
        sigaction(SIGINT,&s,NULL);
        alarm(5);
    }else{
        sigaddset(&set,SIGINT);
    }
    pthread_sigmask(SIG_BLOCK,&set,NULL);
    return 1;
}

/**
 * The function computed by one stage of the pipeline (is computed by an indipendent thread).
 */
void* firstStage::svc(void*){
    if(end){return EOS;}
#ifdef COMPUTE_STATS
    unsigned long t1=ff::getusec();
#endif
    Task* t=new Task(nWorkers);
    struct pfring_pkthdr hdr;
    int r=0;
    uint i;
    u_char *buffer;
    memset(&hdr, 0, sizeof(hdr));
    t->setTimestamp(time(NULL));
    for(i=0; i<maxP; i++){
    	r=pfring_recv(private_handle, &buffer, 0, &hdr, 0);
        if(quit || (r==0 && offline)){
            t->setEof();
            end=true;
            break;
        }else if(r==0){
            break;
        }else{
            dispatchCallback(&hdr, buffer, (u_char*)t);
        }
     }
#ifdef COMPUTE_STATS
     /**Compute service time only if at least one packet has been captured.**/
     if(i!=0){
         ++invocations;
         total_time+=(ff::getusec()-t1);
     }
#endif
     return t;
}

void firstStage::svc_end(){
#ifdef COMPUTE_STATS
    avg_latency=(invocations!=0)?(float)total_time/(float)invocations:-1.0;
#ifndef MULTIPLE_READERS
    std::cout << "\n\n================Latencies================" << std::endl;
#endif
    std::cout << "Average latency (in this case =service time) of reader "<< id <<": " << avg_latency << std::endl;
#endif
}

const int firstStage::get_id(){
    return id;
}

float firstStage::get_avg_latency(){
#ifdef COMPUTE_STATS
    return avg_latency;
#else
    std::cerr << "COMPUTE_STATS not defined." << std::endl;
    return -1.0;
#endif
}

/**
 * Constructor of a generic stage of pipeline.
 * \param id The id of this worker.
 * \param hSize The size of this part of hash table.
 * \param maxActiveFlows Max number of active flows.
 * \param idle Max number of seconds of inactivity (max 24h). (Default is 30).
 * \param lifeTime Max number of life's seconds of a flow (max 24h). (Default is 120).
 * \param flowsPerTaskCheck Number of flows to check when a worker receives a task (-1 is all), default is 1.
 * \param core The id of the core on which this thread should be mapped.
 */
genericStage::genericStage(uint id, uint hSize, uint maxActiveFlows, uint idle, uint lifeTime, int flowsPerTaskCheck, uint core):
                           id(id),hs(hSize),core(core),flowsPerTaskCheck(flowsPerTaskCheck){
#ifdef COMPUTE_STATS
    invocations=total_time=0;
    avg_latency=0;
#endif
    h=new Hash(hs,maxActiveFlows,idle,lifeTime);
}

/**
 * Destructor of the stage.
 */
genericStage::~genericStage(){
    delete h;
}

void genericStage::core_mapping(){
    ff_mapThreadToCpu(core,-20);
}

int genericStage::svc_init(){
    core_mapping();
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s,SIGINT);
    sigaddset(&s,SIGALRM);
    pthread_sigmask(SIG_BLOCK,&s,NULL);
    return 0;
}

/**
 * The function computed by one stage of the pipeline (is computed by an indipendent thread).
 */
void* genericStage::svc(void* p){
#ifdef COMPUTE_STATS
    ++invocations;
    unsigned long t1=ff::getusec();
#endif
    if(p==EOS) return EOS;
    Task* t=(Task*) p;
    ff::squeue<hashElement> *flowsToExport=t->getFlowsToExport(),
                       *flowsToAdd=t->getFlowsToAdd(id);
    time_t now=time(NULL);
    h->updateFlows(flowsToAdd,flowsToExport);
    if(!t->isEof()){
        h->checkExpiration(flowsPerTaskCheck,flowsToExport,&now);
    }else{
    /**If end of file is arrived flush the hash table.**/
        h->flush(flowsToExport);
    }

#ifdef COMPUTE_STATS
    total_time+=(ff::getusec()-t1);
#endif
    return t;
}

void genericStage::svc_end(){
#ifdef COMPUTE_STATS
    avg_latency=(float)total_time/(float)invocations;
    std::cout << "Average latency of worker "<< id <<": " << avg_latency  << std::endl;
#endif
}

float genericStage::get_avg_latency(){
#ifdef COMPUTE_STATS
    return avg_latency;
#else
    std::cerr << "COMPUTE_STATS not defined." << std::endl;
    return -1.0;
#endif
}

/**
 * Exports the flow to the remote collector (also prints it into the file).
 */
void lastStage::exportFlows(){
    int size=q->size();
    ex.sendToCollector(q,flowSequence,out);
    flowSequence+=size;
}

/**
 * Constructor of the last stage of the pipeline.
 * \param out The FILE* where to print exported flows.
 * \param queueTimeout It specifies how long expired flows (queued before delivery) are emitted.
 * \param collector The host of the collector.
 * \param port The port where to send the flows.
 * \param minFlowSize If a TCP flow doesn't have more than minFlowSize bytes isn't exported (0 is unlimited).
 * \param systemStartTime The system start time.
 * \param core The id of the core on which this thread should be mapped.
 */
lastStage::lastStage(FILE* out,uint queueTimeout,const char* collector, uint port, uint minFlowSize, uint32_t systemStartTime, uint core):
                     out(out),qTimeout(queueTimeout),flowSequence(0),minFlowSize(minFlowSize),core(core),q(new std::queue<hashElement>),
                     lastEmission(time(NULL)),ex(collector,port,systemStartTime){
#ifdef COMPUTE_STATS
    invocations=total_time=0;
    avg_latency=0;
#endif
    if(out!=NULL)
        fprintf(out,"IPV4_SRC_ADDR|IPV4_DST_ADDR|OUT_PKTS|OUT_BYTES|FIRST_SWITCHED|LAST_SWITCHED|L4_SRC_PORT|L4_DST_PORT|TCP_FLAGS|"
                "PROTOCOL|SRC_TOS|\n");
}

/**
 * Destructor of the stage.
 */
lastStage::~lastStage(){
    delete q;
}

void lastStage::core_mapping(){
    ff_mapThreadToCpu(core,-20);
}

int lastStage::svc_init(){
    core_mapping();
    /**Blocks SIGINT and unblocks SIGALRM.**/
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set,SIGINT);
    pthread_sigmask(SIG_BLOCK,&set,NULL);
    /**Unblocks SIGALRM.**/
    sigemptyset(&set);
    sigaddset(&set,SIGALRM);
    pthread_sigmask(SIG_UNBLOCK,&set,NULL);

    struct sigaction s;
    bzero( &s, sizeof(s) );
    s.sa_handler=handler;
    sigaction(SIGALRM,&s,NULL);
    return 0;
}

/**
 * The function computed by one stage of the pipeline (is computed by an indipendent thread).
 */
void* lastStage::svc(void* p){
#ifdef COMPUTE_STATS
    ++invocations;
    unsigned long t1=ff::getusec();
#endif
    Task* t=(Task*) p;
    hashElement f;
    ff::squeue<hashElement>* l=t->getFlowsToExport();
    time_t now=time(NULL);
    while(l->size()!=0){
        f=l->front();
        l->pop_front();
        if(!(f.prot==TCP_PROT_NUM && f.dOctets<minFlowSize))
            q->push(f);
        if(q->size()==30){
            exportFlows();
            lastEmission=now;
        }
    }
    if(t->isEof()){
        exportFlows();
        if(out!=NULL){
            fflush(out);
            fclose(out);
            out=NULL;
        }
    /**Exports flows every qTimeout seconds.**/
    }else if((now-lastEmission>=qTimeout) && !q->empty()){
        exportFlows();
        lastEmission=now;
    }
    delete t;
#ifdef COMPUTE_STATS
    total_time+=(ff::getusec()-t1);
#endif
    return GO_ON;
}

void lastStage::svc_end(){
#ifdef COMPUTE_STATS
    avg_latency=(float)total_time/(float)invocations;
    std::cout << "Average latency of exporter: " << avg_latency << std::endl;
#endif
}

float lastStage::get_avg_latency(){
#ifdef COMPUTE_STATS
    return avg_latency;
#else
    std::cerr << "COMPUTE_STATS not defined." << std::endl;
    return -1.0;
#endif
}

int workerAndExporter::svc_init(){
    int x=exporter->svc_init();
    worker->core_mapping();
    return x;
}

/**
 * Constructor of the stage.
 * \param w The stage that adds the flows to the hash table.
 * \param e The stage that exports the expired flows.
 */
workerAndExporter::workerAndExporter(genericStage* w, lastStage* e):worker(w),exporter(e){;}

/**
 * The function computed by one stage of the pipeline (is computed by an indipendent thread).
 */
void* workerAndExporter::svc(void* t){
    return exporter->svc(worker->svc(t));
}

void workerAndExporter::svc_end(){
    worker->svc_end();
    exporter->svc_end();
}

#ifdef MULTIPLE_READERS

CThread::CThread(){}
virtual CThread::~CThread(){}

/** Returns true if the thread was successfully started, false if there was an error starting the thread */
bool CThread::start(){
   return (pthread_create(&_thread, NULL, execFun, this) == 0);
}

/** Will not return until the internal thread has exited. */
void CThread::wait(){
   (void) pthread_join(_thread, NULL);
}


static void * CThread::execFun(void * t) {((CThread *)t)->execute(); return NULL;}





 readerThread::readerThread(ff::FFBUFFER* outbuffer, firstStage *reader):outbuffer(outbuffer),reader(reader)
#ifdef COMPUTE_STATS
 ,pushlost(0)
#endif
 {;}

 readerThread::~readerThread(){
     if(reader) delete reader;
 }

 void readerThread::execute(){
     reader->svc_init();
     void* result;
     while(true){
         result=reader->svc(NULL);
         while(!outbuffer->push(result)){
#ifdef COMPUTE_STATS
             ++pushlost;
#endif
         }
         if(result==EOS) break;
     }
 }

 void readerThread::stats(std::ostream & out){
#ifdef COMPUTE_STATS
     out << "===========Reader "<< reader->get_id() <<"==========" << "\n";
     reader->svc_end();
     out << "Push lost: " << pushlost << "\n";
#endif
 }

 float readerThread::get_avg_latency(){
     return reader->get_avg_latency();
 }



 gatherThread::gatherThread(ff::FFBUFFER **inbuffers, ff::FFBUFFER *outbuffer, uint numBuffers, ff::ff_node *worker):
     inbuffers(inbuffers),outbuffer(outbuffer),numBuffers(numBuffers),terminated(0),worker(worker)
#ifdef COMPUTE_STATS
 ,poplost(0),pushlost(0)
#endif
 {;}

 void gatherThread::execute(){
     int i=0;
     Task *t;
     void *returned;
     worker->svc_init();
     while(terminated<numBuffers){
         while(!inbuffers[i]->pop((void**)&t)){
             i=(i+1)%numBuffers;
#ifdef COMPUTE_STATS
             ++poplost;
#endif
         }
         if(t==EOS){
             ++terminated;
         }else{
             returned=worker->svc(t);
             if(outbuffer){
                 while(!outbuffer->push(returned)){
#ifdef COMPUTE_STATS
                     ++pushlost;
#endif
                 }
             }
             i=(i+1)%numBuffers;
         }
     }
     if(outbuffer)
         while(!outbuffer->push(EOS));
 }

 void gatherThread::stats(std::ostream & out){
#ifdef COMPUTE_STATS
     out << "===========Gather==========" << "\n";
     worker->svc_end();
     out << "Pop lost: " << poplost << "\n";
     out << "Push lost: " << pushlost << "\n";
#endif
 }


 my_pipeline::my_pipeline(int in_buffer_entries, int out_buffer_entries, bool fixedsize){
     ff::ff_pipeline(in_buffer_entries,out_buffer_entries,fixedsize);
 }

 int my_pipeline::create_input_buffer(int nentries, bool fixedsize) {
     return ff::ff_pipeline::create_input_buffer(nentries,fixedsize);
 }
#endif
