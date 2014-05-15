/*
 * ffProbe.cpp
 *
 * \date 14/mag/2010
 * \author Daniele De Sensi (d.desensi.software@gmail.com)
 * =========================================================================
 *  Copyright (C) 2010-2014, Daniele De Sensi (d.desensi.software@gmail.com)
 *
 *  This file is part of Peafowl.
 *
 *  Peafowl is free software: you can redistribute it and/or
 *  modify it under the terms of the Lesser GNU General Public
 *  License as published by the Free Software Foundation, either
 *  version 3 of the License, or (at your option) any later version.

 *  Peafowl is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  Lesser GNU General Public License for more details.
 *
 *  You should have received a copy of the Lesser GNU General Public
 *  License along with Peafowl.
 *  If not, see <http://www.gnu.org/licenses/>.
 *
 * =========================================================================
 *
 * The main file.
 */

#ifdef COMPUTE_STATS
#define TRACE_FASTFLOW
#endif

#define BUFFER_SIZE 32
#include "task.hpp"
#include "flow.hpp"
#include "workers.hpp"
#include "utils.hpp"
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <iostream>
#include <ff/pipeline.hpp>


/**
 * Prints information on the program.
 * \param progName The name of the program.
 */
void printHelp(char* progName){
fprintf(stderr,"\nusage: %s -i <captureInterface> [--sequential] [-d <idleTimeout>] [-l <lifetimeTimeout>]\n"
        "[-q <queueTimeout>] [<-r readers>] [-w <workers>] [<-e exporters>] [-j | --cores] <cores>\n"
        "[-u <chip>] [-s <hashSize>] [-m <maxActiveFlows>] [-x <cnt>] [-f <outputFile>] [-z <flowsPerTaskCheck>]\n"
        "[-c | --collector] <collector> [-p | --port] <port> [-y <minFlowSize>] [-n | --nopromisc] [-h]\n\n\n", progName);
fprintf(stderr,"-i <captureInterface>          | Interface name from which packets are captured. You can also specify more than one\n"
        "                               | interfaces separating them by an underscore (e.g. -i eth1_eth2_..._ethn). In this case you have also to\n"
        "                               | specify -r n.\n");
fprintf(stderr,"[--sequential]                 | Executes the probe sequentially.\n");
fprintf(stderr,"[-d <idleTimeout>]             | It specifies the maximum (seconds) flow idle lifetime [default 30]\n");
fprintf(stderr,"[-l <lifetimeTimeout>]         | It specifies the maximum (seconds) flow lifetime [default 120]\n");
fprintf(stderr,"[-q <queueTimeout>]            | It specifies how long (seconds) expired flows (queued before delivery) are emitted [default 30]\n");
fprintf(stderr,"[-r <readers>]                 | It specifies how many reader threads read from different interfaces) [default 1].\n"
        "                               | If you want to use more than one reader you have to recompile ffProbe with -DMULTIPLE_READERS.\n");
fprintf(stderr,"[-w <workers>]                 | It specifies how many threads manage the hash table [default 1].\n"
        "                               | HashSize %% (workers) must be equals to 0\n");
fprintf(stderr,"[-e <exporters>]               | It specifies if the exporter is executed by an indipendent thread (1) or if it's executed\n"
        "                               | by the same thread of one of the workers (0) [default 1].\n");
fprintf(stderr,"[-j | --cores] <cores>  | It specifies the identifiers of the cores on which the stages of the pipeline should be mapped [default 0].\n"
        "                               | The cores identifiers must be separated by an underscore (e.g. 0_1_2_3). The stages of the pipeline will be mapped\n"
        "                               | in the same order.\n");
fprintf(stderr,"[-u <chip>]                    | It specifies the identifier of the chip on which the pipeline should be mapped [default 0].\n"
        "                               | If it is composed by a number of threads higher than the number of core on the chip the other stages\n"
        "                               | will be mapped on the successive cores.\n");
fprintf(stderr,"[-s <hashSize>]                | It specifies the size of the hash table where the flows are stored [default 32762].\n"
        "                               | HashSize %% (workers) must be equals to 0, moreover HashSize should not be a power of 2 because tha hash function\n"
                "                               | is h(x)=x %% HashSize\n");
fprintf(stderr,"[-m <maxActiveFlows>]          | Limit the number of active flows for one worker. This is useful if you want to limit the\n"
        "                               | memory allocated to ffProbe [default 3000000]\n");
fprintf(stderr,"[-x <cnt>]                     | Cnt is the maximum number of packets to process before returning from reading, but is not a minimum\n"
        "                               | number. If less than cnt packets are present, only those packets will be processed. If no packets are presents,\n"
        "                               | read returns immediately. A  value of -1 means \"process packets until there is at least one packet on the buffer\".\n"
        "                               | This can be dangerous because if the packets rate is very high the program will always find packets in the buffer\n"
        "                               | and so can fill the memory. A value of -1 when reading a live capture causes all the packets in the file to be\n"
        "                               | processed [default 10000]\n");
fprintf(stderr,"[-f <outputFile>]              | Print the flows in textual format on a file\n");
fprintf(stderr,"[-z <flowsPerTaskCheck>]       | Number of flows to check for expiration after the arrival of a task to a worker. (-1 is all) [default 200]\n");
fprintf(stderr,"[-c | --collector] <collector> | Host of the collector [default 127.0.0.1]\n");
fprintf(stderr,"[-p | --port] <port>           | Port of the collector [default 2055]\n");
fprintf(stderr,"[-y <minFlowSize>]             | Minimum TCP flow size (in bytes). If a TCP flow is shorter than the specified size the flow\n"
        "                               | is not emitted. 0 is unlimited [default unlimited]\n");
fprintf(stderr,"[-n | --nopromisc]             | Put the interface into 'No promiscuous' mode.\n");
fprintf(stderr,"[-h]                           | Prints this help\n");
}


/* An array describing valid long options.  */
static const struct option long_options[] = {
  { "sequential",     no_argument, NULL, 0 },
  { "cores",     required_argument, NULL, 'j' },
  { "nopromisc",     no_argument, NULL, 'n' },
  { "collector",     no_argument, NULL, 'c' },
  { "port",     no_argument, NULL, 'p' },
  { NULL,       0, NULL, 0   }   /* Required at end of array.  */
};

/**Statistics collection.**/
extern pfring** handle;
extern uint numReaders;
extern uint* plast;

int main(int argc, char** argv){
  char *interface=NULL;
    const char *collector="127.0.0.1";
    int c,cnt=10000,flowsPerTaskCheck=200;
    uint minFlowSize=0, queueTimeout=30,lifetime=120,readers=1,workers=1,indipendent_exporter=1,idle=30,maxActiveFlows=3000000u,hashSize=32762,chip=0,promisc=1;
    ushort port=2055;
    uint *cores=NULL;
    bool sequential=false;
    FILE* output=NULL;
    /**Args parsing.**/
    int longindex;
    while ((c = getopt_long (argc, argv, "i:d:l:q:t:r:w:e:j:u:s:m:x:f:z:c:p:y:nh", long_options, &longindex)) != -1)
        switch (c){
            case 'i':
                interface = optarg;
                break;
            case 'd':
                idle = atoi(optarg);
                break;
            case 'l':
                lifetime = atoi(optarg);
                break;
            case 'q':
                queueTimeout = atoi(optarg);
                break;

            case 'r':
                readers = atoi(optarg);
                if(readers < 1){
                    std::cerr << "You need at least one reader. If you want to execute the probe sequentially specify --sequential parameter.\n";
                    exit(-1);
                }
                sequential=false;
                break;
            case 'w':
                workers = atoi(optarg);
                if(readers < 1){
                    std::cerr << "You need at least one worker. If you want to execute the probe sequentially specify --sequential parameter.\n";
                    exit(-1);
                }
                break;
            case 'e':
                indipendent_exporter = atoi(optarg);
                if(indipendent_exporter!=0 && indipendent_exporter!=1){
                    printf("ERROR: -e [<0|1>].\n");
                    exit(-1);
                }
                break;
            case 'j':{
                //TODO MANAGE SEQUENTIAL
                uint numThreads;
                if(sequential)
                    numThreads=1;
                else
                    numThreads=readers+workers+indipendent_exporter;
                cores=new uint[numThreads];
                char* identifier=strtok(optarg,"_");
                for(uint i=0; i<numThreads; i++){
                    if(identifier==NULL){
                        std::cerr << "You have to specify a number of cores equal to readers+workers+exporter.\n";
                        exit(-1);
                    }
                    cores[i]=atoi(identifier);
                    identifier=strtok(NULL,"_");
                }
                if(identifier!=NULL)
                    std::cerr << "You specified more than n identifiers (where n=readers+workers+exporter). "
                                 "The probe will consider only the first n of them.\n" << std::endl;
                break;
            }
            case 'u':
                   chip = atoi(optarg);
                   break;
            case 's':
                hashSize = atoi(optarg);
                break;
            case 'm':
                maxActiveFlows = atoi(optarg);
                break;
            case 'x':
                cnt=atoi(optarg);
                break;
            case 'f':
                output=fopen(optarg,"w");
                if(output==NULL)
                    perror("Opening output file: ");
                break;
            case 'z':
                flowsPerTaskCheck=atoi(optarg);
                break;
            case 'c':
                collector=optarg;
                break;
            case 'p':
                port=atoi(optarg);
                break;
            case 'y':
                minFlowSize=atoi(optarg);
                break;
            case 'n':
                promisc=0;
                break;
            case 'h':
                printHelp(argv[0]);
                return 1;
            case '?':
                printHelp(argv[0]);
                return 1;
            case 0:
                if(strcmp( "sequential", long_options[longindex].name ) == 0 )
                    sequential = true;
                break;
            default:
                fprintf(stderr,"Unknown option.\n");
                exit(-1);
         }
    if(interface==NULL){
        printf("ERROR: -i <interface> required.\n");
        exit(-1);
    }
    assert(hashSize%(workers)==0);

    timeval systemStartTime;
    gettimeofday(&systemStartTime,NULL);
    uint32_t sst=systemStartTime.tv_sec*1000+systemStartTime.tv_usec/1000;
    handle=new pfring*[readers];
    numReaders=readers;
    plast=new uint[readers];
    for(uint i=0; i<readers; i++) plast[i]=0;
    /**Sequential execution**/
    if(sequential){
#ifdef MULTIPLE_READERS
        std::cerr << "You defined -DMULTIPLE_READERS so you have to use more than one reader.\n" << std::endl;
        exit(-1);
#else
        /**Signal handling.**/
        struct sigaction s;
        bzero( &s, sizeof(s) );
        s.sa_handler=handler;
        sigaction(SIGALRM,&s,NULL);
        sigaction(SIGINT,&s,NULL);
        const uint core=(cores!=NULL)?cores[0]:1;
        /**Creates the first stage of the pipeline (reader).**/
        firstStage sniffer(workers,interface,promisc,cnt,hashSize,0,core);
        genericStage worker(0,hashSize,maxActiveFlows,idle,lifetime,flowsPerTaskCheck,core);
        lastStage last(output,queueTimeout,collector,port,minFlowSize,sst,core);
        ff_mapThreadToCpu(core,-20);
        alarm(5);
        void * t;
        while((t=sniffer.svc(NULL))!=(void*) ff::FF_EOS)
            last.svc(worker.svc(t));
        sniffer.svc_end();
        worker.svc_end();
        last.svc_end();
#ifdef COMPUTE_STATS
        float latency[1];
        latency[0]=worker.get_avg_latency();
        generateSuggestions(latency,0,sniffer.get_avg_latency(),last.get_avg_latency(),indipendent_exporter);
#endif
#endif
    }else{
    /**Parallel execution.**/
        /**Blocks the SIGALRM and SIGINT signals.**/
        sigset_t s;
        sigemptyset(&s);
        sigaddset(&s,SIGINT);
        sigaddset(&s,SIGALRM);
        pthread_sigmask(SIG_BLOCK,&s,NULL);

        /**
         * Create the array with the identifiers of the cores on which the threads must be mapped.
         * The elements from 0 to readers-1 will be the identifiers of the cores on which the readers must be mapped.
         * The elements from readers to readers+workers-1 will be the identifiers of the cores on which the workers must be mapped.
         * The last element of the array will be the identifier of the core on which the exporter must be mapped.
         */
        uint numThreads=readers+workers+indipendent_exporter;
        if(cores==NULL){
            cores=new uint[numThreads];
            generateMapping(cores,numThreads,chip);
        }
        if(readers>1){
        /**More than one reader.**/
#ifdef MULTIPLE_READERS
            readerThread **rThreads=new readerThread*[readers];
            ff::FFBUFFER **rBuffers=new ff::FFBUFFER*[readers];
            /**Extracts the names of the interfaces.**/
            char* iface=strtok(interface,"_");
            for(uint i=0; i<readers; i++){
                if(iface==NULL){
                    std::cerr << "You have to specify a number of interface equal to the parameter specified in -r.\n";
                    exit(-1);
                }
                rBuffers[i]=new ff::FFBUFFER(BUFFER_SIZE,true);
                rBuffers[i]->init();
                rThreads[i]=new readerThread(rBuffers[i],new firstStage(workers,iface,promisc,cnt,hashSize,i,cores[i]));
                iface=strtok(NULL,"_");
            }
            if(iface!=NULL)
                std::cerr << "You specified more than n interfaces (where n is the parameter specified in -r n). "
                        "The probe will read only from the first n of them.\n" << std::endl;

            genericStage** workerNodes=new genericStage*[workers];
            int workerHs=hashSize/workers;
            for(uint i=0; i<workers; i++)
                workerNodes[i]=new genericStage(i,workerHs,maxActiveFlows,idle,lifetime,flowsPerTaskCheck,cores[i+readers]);
            my_pipeline x(BUFFER_SIZE,BUFFER_SIZE,true);
            for(uint i=1; i<workers-1; i++)
                x.add_stage(workerNodes[i]);

            /**Creates the last stage of the pipeline (exported).**/
            lastStage *last=new lastStage(output,queueTimeout,collector,port,minFlowSize,sst,cores[numThreads-1]);
            workerAndExporter *wae=NULL;
            ff::ff_node *gatherNode=workerNodes[0];;
            if(indipendent_exporter){
                if(workers>1)
                    x.add_stage(workerNodes[workers-1]);
                x.add_stage(last);
            }else{
                wae=new workerAndExporter(workerNodes[workers-1],last);
                if(workers>1)
                    x.add_stage(wae);
                else
                    gatherNode=wae;
            }
            gatherThread *gThread;
            if(x.cardinality()>0){
                x.run();
                x.create_input_buffer(BUFFER_SIZE,true);
                gThread=new gatherThread(rBuffers, x.get_in_buffer(), readers, gatherNode);
            }else
                gThread=new gatherThread(rBuffers, NULL, readers, gatherNode);
            /**Start the readers.**/
            for(uint i=0; i<readers; i++)
                rThreads[i]->start();
            gThread->start();

            rThreads[0]->wait();
            std::cout << "\n\n";
            rThreads[0]->stats(std::cout);

            /**Wait the termination of all the threads.**/
            for(uint i=1; i<readers; i++){
                rThreads[i]->wait();
                rThreads[i]->stats(std::cout);
            }
            gThread->wait();
            gThread->stats(std::cout);
            std::cout << "\n";
            x.wait();
            x.ffStats(std::cout);
            //TODO CHECK IF THE COMPUTATION OF THE SUGGESTION IS CORRECT IN THIS CASE
#ifdef COMPUTE_STATS
            float *workers_latencies=new float[workers];
            float temp=0;
#endif
            for(uint i=0; i<readers; i++){
#ifdef COMPUTE_STATS
                /**Multiple client theorem: the bandwidth of the data arriving to the gather is equal to the sum of the bandwidth of the readers.**/
                temp+=(1.0/(rThreads[i]->get_avg_latency()));
#endif
                delete rThreads[i];
                delete rBuffers[i];
            }
            delete[] rThreads;
            delete[] rBuffers;
            for(uint i=0; i<workers; i++){
#ifdef COMPUTE_STATS
                workers_latencies[i]=workerNodes[i]->get_avg_latency();
#endif
                delete workerNodes[i];
            }
#ifdef COMPUTE_STATS
            generateSuggestions(workers_latencies,workers,1.0/temp,last->get_avg_latency(),indipendent_exporter);
            delete[] workers_latencies;
#endif
            delete[] workerNodes;
            if(wae) delete wae;
            delete last;
#else
            std::cerr << "If you want to use more than one reader you have to recompile ffProbe with -DMULTIPLE_READERS.\n" << std::endl;
            exit(-1);
#endif
        }else{
#ifdef MULTIPLE_READERS
            std::cerr << "You defined -DMULTIPLE_READERS. If you want to use only one reader recompile ffProbe without -DMULTIPLE_READERS.\n" << std::endl;
            exit(-1);
#else
        /**Only one reader.**/
            ff::ff_pipeline pipe(BUFFER_SIZE,BUFFER_SIZE,true);
            firstStage sniffer(workers,interface,promisc,cnt,hashSize,0,cores[0]);
            pipe.add_stage(&sniffer);
            genericStage** stages=new genericStage*[workers];
            int workerHs=hashSize/workers;
            for(uint i=0; i<workers; i++)
                stages[i]=new genericStage(i,workerHs,maxActiveFlows,idle,lifetime,flowsPerTaskCheck,cores[i+1]);
            /**Adds the workers to the pipeline.**/
            for(uint i=0; i<workers-1; i++)
                pipe.add_stage(stages[i]);

            workerAndExporter *wae=NULL;
            /**Creates the last stage of the pipeline (exported).**/
            lastStage last(output,queueTimeout,collector,port,minFlowSize,sst,cores[numThreads-1]);
            if(indipendent_exporter){
                pipe.add_stage(stages[workers-1]);
                pipe.add_stage(&last);
            }else{
                wae=new workerAndExporter(stages[workers-1],&last);
                pipe.add_stage(wae);
            }
            /**Starts the computation and waits for the end.**/
            pipe.run_and_wait_end();
            std::cout << std::endl;
            pipe.ffStats(std::cout);
            if(wae) delete wae;
#ifdef COMPUTE_STATS
            float *avg_latencies=new float[workers];
#endif
            for(uint i=0; i<workers; i++){
#ifdef COMPUTE_STATS
                avg_latencies[i]=stages[i]->get_avg_latency();
#endif
                delete stages[i];
            }
#ifdef COMPUTE_STATS
            generateSuggestions(avg_latencies,workers,sniffer.get_avg_latency(),last.get_avg_latency(),indipendent_exporter);
            delete[] avg_latencies;
#endif
            delete[] stages;
#endif
        }
        delete[] cores;
    }
    delete[] plast;
    delete[] handle;
    return 0;
}
