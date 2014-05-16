/*
 * utils.cpp
 *
 * \date 5/7/2011
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
 * Implementation of utility functions.
 */

#include <stdio.h>
#include <iostream>
#include <vector>
#include "utils.hpp"

/**
 * Create the array with the identifiers of the cores on which the threads must be mapped.
 * The elements from 0 to readers-1 will be the identifiers of the cores on which the readers must be mapped.
 * The elements from readers to readers+workers-1 will be the identifiers of the cores on which the workers must be mapped.
 * The last element of the array will be the identifier of the core on which the exporter must be mapped.
 */


bool contains(std::vector<std::pair<uint,uint> > &v, std::pair<uint,uint> &element){
    for(uint i=0; i<v.size(); i++)
        if(v[i].first==element.first && v[i].second==element.second) return true;
    return false;
}

/**
 * Extract infos about the displacement of the cores on the chips of the machine.
 * \param v This vector will be filled with the identifiers of the cores. If we have n cores per chip the vector
 *          will be divided in blocks of n elements. Each block will represents the identifiers of the core on a chip.
 * Returns the number chips on the machine or 0 on error.
 */
uint captureCpuInfos(std::vector<uint> &processors_to_use){
    FILE *file = fopen("./tmpcpuinfo", "r");
    if(!file) return 0;
    uint starting_core_id=0,num_chips=0;
    char c;

    /**Reads the number of chips.**/
    while(!feof(file)){
        if(fscanf(file,"%c",&c)!=1) return 0;
        if(c=='\n') break;
        num_chips=c-'0';
    }
    /**Reads the identifier of the first core.**/
    while(!feof(file)){
        if(fscanf(file,"%c",&c)!=1) return 0;
        if(c=='\n') break;
        starting_core_id=c-'0';
    }
    /**Read the physical identifiers of the chips on which the core are displaced.**/
    std::vector<uint> phy_ids;
    while(!feof(file)){
        if(fscanf(file,"%c",&c)!=1) return 0;
        if(c=='\n') break;
        if(c==' ') continue;
        phy_ids.push_back(c-'0');
    }
    /**Read the core identifiers.**/
    std::vector<uint> core_ids;
    while(!feof(file)){
        if(fscanf(file,"%c",&c)!=1) return 0;
        if(c=='\n') break;
        if(c==' ') continue;
        core_ids.push_back(c-'0');

    }
    std::vector<std::pair<uint,uint> > pairs;
    std::pair<uint,uint> element;
    /**
     * If we have two pair with the same <phy_id,core_id> then they will be two 'virtual processors' (hyperthreading).
     * It seems that this application doesn't takes any advantage from hyperthreading so we will ignore it and we will
     * run only one thread per core.
     */
    for(uint j=0; j < num_chips; j++){
        for(uint i=0; i < core_ids.size(); i++){
            element=std::pair<uint,uint>(phy_ids[i],core_ids[i]);
            if(element.first == j && !contains(pairs,element)){
                pairs.push_back(element);
                processors_to_use.push_back(starting_core_id+i);
            }
        }
    }
    fclose(file);
    return num_chips;
}

void generateMapping(uint* cores, uint numThreads, uint chip){
    std::vector<uint> processors_to_use;
    uint num_chips=captureCpuInfos(processors_to_use),num_real_cores=processors_to_use.size();
    uint cores_per_chip=num_real_cores/num_chips;
    uint starting_processor=chip*cores_per_chip;
    if(num_chips==0){
        for(uint i=0; i<numThreads; i++)
            cores[i]=i;
        std::cerr << "ATTENTION: It's not possible to analyze the /proc/cpuinfo file." << std::endl;
    }else{
        for(uint i=0; i<numThreads; i++){
            cores[i]=processors_to_use[(i+starting_processor)%num_real_cores];
        }
        if(numThreads>num_real_cores){
            std::cout << "ATTENTION: You are using a number of threads greater than the number of physical cores available. This can lead to inefficiency"
                         " in execution. You have " << num_real_cores << " physical cores available and you are trying to use "
                         << numThreads << " threads" << std::endl;
        }
    }
}

/**Generate suggestions about a possible reduction/increase of the parallelism degree.**/
void generateSuggestions(float *workers_latencies, uint workers, float reader_latency, float exporter_latency, uint indipendent_exporter, uint readers){
    std::cout << "\n\n=========Suggestions about the parallelism degree=========" << std::endl;
    float sum=0;
    uint suggested_workers;
    if(workers==0){
        suggested_workers=ceil(workers_latencies[0]/reader_latency);
        std::cout << "You are using the sequential version of the probe. Under this traffic conditions you may improve the performances of"
                " the probe using " << suggested_workers << " workers.\nTry to run the program with -w " << suggested_workers << std::endl;
    }else{
        for(uint i=0; i<workers; i++)
            sum+=workers_latencies[i];
//TODO CHECK IF THIS FORMULA IS OK FOR MULTIPLE_READERS
        suggested_workers=ceil(sum/reader_latency);
        /**
         * We check if the bottleneck is the reader stage or the workers.
         * In our case is always convenient to have the reader as bottleneck, because otherwise it will be often blocked on the
         * queue to the worker. If the reader is blocked trying to push the task in the queue it will lose many packets.
         */
        if(suggested_workers<workers)
            std::cout << "Under this traffic conditions you can try to use " << suggested_workers << " "
                         "workers and you may obtain the same performances.\n"
                         "Try to run the program with -w " << suggested_workers << std::endl;
        else if(suggested_workers==workers)
            std::cout << "Under this traffic conditions, "
                         "if you want to obtain these performances, you should not reduce the number of workers." << std::endl;
        /**
         * In this case the workers are the bottlenecks of the pipeline and we compute the minimum number of
         *  workers to use to avoid that the workers are the bottlenecks of the pipeline.
         */
        else
            std::cout << "If you have performance problems, under this traffic conditions you may "
                         "improve your performances using " << suggested_workers << " workers.\n"
                          "Try to run the program with -w " << suggested_workers << std::endl;
    }

    if((sum/suggested_workers) + exporter_latency<reader_latency){
        if(indipendent_exporter)
            std::cout << "\nWith " << suggested_workers << " workers and under this traffic conditions you can also try to aggregate together the exporter "
                          "with the last worker.\n"
                          "Try to run the program with -w "<< suggested_workers <<" -e 0" << std::endl;
    }
    else if(suggested_workers<workers && ((sum/(suggested_workers+1)) + exporter_latency < reader_latency)){
        if(indipendent_exporter)
            std::cout << "\nAlternatively you can try to use " << suggested_workers+1 <<" workers and aggregate the exporter with the last of them.\n"
                          "Try to run the program with -w " << suggested_workers+1 << " -e 0" << std::endl;
    }
    else if(!indipendent_exporter)
        std::cout << "\nIf you have performance problems you can try to run the exporter in an indipendent thread. "
                "Try to run the program with -e 1" << std::endl;

    std::cout << "\n\n\n";
}
