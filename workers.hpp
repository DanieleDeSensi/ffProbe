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

#ifndef WORKERS_HPP
#define WORKER_HPP
#include <deque>
#include <pcap.h>
#include <sys/poll.h>
#include <ff/node.hpp>
#include <ff/mapping_utils.hpp>
#include <ff/pipeline.hpp>
#include <ff/gt.hpp>
#include <pfring.h>
#undef min
#undef max
#include <queue>
#include <signal.h>
#include <errno.h>
#include "task.hpp"
#include "hashTable.hpp"


/**
 * The function called by pcap_dispatch when a packet arrive.
 * \param user A param passed by the worker.
 * \param phdr The header of the packet.
 * \param pdata The packet.
 */
void dispatchCallback(const struct pfring_pkthdr *phdr, const u_char *pdata , const u_char *user_bytes);

/**
 * Signal handler for SIGINT.
 */
void handler(int i);


/**
 * First stage of the pipeline (captures the packets).
 */
class firstStage: public ff::ff_node{
private:
    uint maxP, ///< Maximum number of packet to read from the device (or from the .pcap file)
         nWorkers, ///< Number of workers
         id, ///< Identifier of the reader
         core; ///<The id of the core on which this thread should be mapped.
    bool offline, ///< True if the device is a .pcap file
         end; ///< When end is true this node must return FF_EOS.
    pfring *private_handle;
#ifdef COMPUTE_STATS
    unsigned long invocations,total_time;
    float avg_latency;
#endif
public:
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
    firstStage(int nw, char* device, uint promisc, int cnt, int h, uint id, uint core);

    /**
     * Destructor of the first stage.
     */
    ~firstStage();

    void core_mapping();

    int svc_init();

    /**
     * The function computed by one stage of the pipeline (is computed by an indipendent thread).
     */
    void* svc(void*);

    void svc_end();

    const int get_id();

    float get_avg_latency();
};


/**
 * This worker adds the flows to the hash table.
 */
class genericStage:public ff::ff_node{
private:
    uint id,hs,core; ///<The id of the core on which this thread should be mapped.
    int flowsPerTaskCheck;
    Hash* h;
#ifdef COMPUTE_STATS
        unsigned long invocations,total_time;
        float avg_latency;
#endif
public:
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
    genericStage(uint id, uint hSize, uint maxActiveFlows, uint idle, uint lifeTime, int flowsPerTaskCheck, uint core);

    /**
     * Destructor of the stage.
     */
    ~genericStage();

    void core_mapping();

    int svc_init();

    /**
     * The function computed by one stage of the pipeline (is computed by an indipendent thread).
     */
    void* svc(void* p);

    void svc_end();

    float get_avg_latency();
};

/**
 * The last stage of the pipeline (exports the expired flows).
 */
class lastStage:public ff::ff_node{
private:
    FILE* out; ///<File where to print the flows in textual format.
    uint qTimeout, ///<It specifies how long expired flows (queued before delivery) are emitted
        flowSequence, ///<Sequence number for the flows to export
        minFlowSize,///<Minimum tcp flows size
        core;///<The id of the core on which this thread should be mapped.
    std::queue<hashElement>* q; ///<Queue of expired flows
    time_t lastEmission; ///<Time of the last export
    Exporter ex;
#ifdef COMPUTE_STATS
        unsigned long invocations,total_time;
        float avg_latency;
#endif

    /**
     * Exports the flow to the remote collector (also prints it into the file).
     */
    void exportFlows();
public:
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
    lastStage(FILE* out,uint queueTimeout,const char* collector, uint port, uint minFlowSize, uint32_t systemStartTime, uint core);

    /**
     * Destructor of the stage.
     */
    ~lastStage();

    void core_mapping();

    int svc_init();

    /**
     * The function computed by one stage of the pipeline (is computed by an indipendent thread).
     */
    void* svc(void* p);

    void svc_end();

    float get_avg_latency();
};

/**
 * A stage that adds the flows to the hash table and exports the expired flows.
 */
class workerAndExporter: public ff::ff_node{
private:
    genericStage* worker;
    lastStage* exporter;
public:
    int svc_init();

    /**
     * Constructor of the stage.
     * \param w The stage that adds the flows to the hash table.
     * \param e The stage that exports the expired flows.
     */
    workerAndExporter(genericStage* w, lastStage* e);

    /**
     * The function computed by one stage of the pipeline (is computed by an indipendent thread).
     */
    void* svc(void* t);

    void svc_end();
};


#ifdef MULTIPLE_READERS
class CThread{
public:
   CThread();
   virtual ~CThread();

   /** Returns true if the thread was successfully started, false if there was an error starting the thread */
   bool start();

   /** Will not return until the internal thread has exited. */
   void wait();

protected:
   /** Implement this method in your subclass with the code you want your thread to run. */
   virtual void execute() = 0;

private:
   static void * execFun(void * t);

   pthread_t _thread;
};



class readerThread: public CThread{
private:
    ff::FFBUFFER* outbuffer;
    firstStage *reader;
#ifdef COMPUTE_STATS
    long unsigned int pushlost;
#endif
public:
    readerThread(ff::FFBUFFER* outbuffer, firstStage *reader);

    ~readerThread();

    void execute();

    void stats(std::ostream & out);

    inline float get_avg_latency();

};

class gatherThread: public CThread{
private:
    ff::FFBUFFER **inbuffers,*outbuffer;
    uint numBuffers,terminated;
    ff::ff_node *worker;
#ifdef COMPUTE_STATS
    long unsigned int poplost,pushlost;
#endif
public:
    gatherThread(ff::FFBUFFER **inbuffers, ff::FFBUFFER *outbuffer, uint numBuffers, ff::ff_node *worker);

    void execute();

    void stats(std::ostream & out);
};

/**This is created only to have the 'create_input_buffer' method public.**/
class my_pipeline: public ff::ff_pipeline{
public:
    my_pipeline(int in_buffer_entries, int out_buffer_entries, bool fixedsize);

    int create_input_buffer(int nentries, bool fixedsize);
};
#endif
#endif /**WORKERS_HPP**/
