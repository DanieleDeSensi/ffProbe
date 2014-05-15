/*
 * hashTable.hpp
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
 * Implementation of the hash table used by the workers to insert the flows.
 */

#ifndef HASHTABLE_HPP_
#define HASHTABLE_HPP_
#include <cassert>
#include <limits>
#include <algorithm>

/**
 * Hash table
 */
class Hash{
private:
    hashElement **h;      ///<The hash table.
    uint *sizes, ///<Sizes of the collision lists.
         *capacities; ///<<Capacities of the collision lists.
    uint size,            ///<Number of row of the table.
        maxActiveFlows,   ///<Max number of active flows.
        activeFlows,      ///<Number of active flows.
        lasti,      ///<Used to check the expiration of the flows.
        lastj,               ///<Pointers to the last node checked.
        idle,              ///<Max number of seconds of inactivity.
        lifetime;         ///<Max number of life's seconds of a flow.
public:
    /**
     * Constructor of the hash table.
     * \param d Number of row of the table.
     * \param maxActiveFlows Maximum number of active flows.
     * \param idle Max number of seconds of inactivity.
     * \param lifeTime Max number of life's seconds of a flow.
     */
    Hash(uint d, uint maxActiveFlows, uint idle, uint lifetime):h(new hashElement*[d]),size(d)
    ,maxActiveFlows(maxActiveFlows),activeFlows(0),lasti(0),lastj(0),idle(idle),lifetime(lifetime){
        sizes=new uint[d];
        capacities=new uint[d];
        for(uint i=0; i<d; i++){
            h[i]=(hashElement*)calloc(10,sizeof(hashElement));
            sizes[i]=0;
            capacities[i]=10;
        }
    }

    /**
     * Destructor of the hash table.
     */
    ~Hash(){
        for(uint i=0; i<size; i++)
            free((void*)h[i]);
        delete[] h;
        delete[] sizes;
        delete[] capacities;
    }

    /**
     * Adds (or updates) some flows. If the hash table has the max number of active flows, adds to l a flow and remove it from
     * the hash table.
     * \param flowsToAdd A list of flows to add.
     * \param l A pointer to a list of expired flows.
     */
    void updateFlows(ff::squeue<hashElement>* flowsToAdd, ff::squeue<hashElement>* l){
        hashElement f;
        uint i,x,newcapacity,prefetch_id;
        f.First.tv_sec=0;
        while(flowsToAdd->size()!=0){
            f=flowsToAdd->front();
            flowsToAdd->pop_front();
            i=f.hashId%size;
/**
 * To speed up the execution we can prefetch the collision list in which the next flow will be stored.
 * In general this list will not be the one successive to the current one. For this reason we need to prefetch it explicitly.
 */
#ifdef __GNUC__
            if(flowsToAdd->size()){
                prefetch_id=(flowsToAdd->front()).hashId;
                __builtin_prefetch(h[prefetch_id], 1, 0);
                __builtin_prefetch(&sizes[prefetch_id], 1, 0);
                __builtin_prefetch(&capacities[prefetch_id], 1, 0);
            }
#endif
            /**Searches the node.**/
            x=0;
            while(x<sizes[i] && !equals(h[i][x],f)) ++x;
            /**Updates flow.**/
            if(x<sizes[i]){
                ++(h[i][x].dPkts);
                h[i][x].dOctets+=f.dOctets;
                h[i][x].Last=f.First;
                h[i][x].tcp_flags|=f.tcp_flags;
              }else{
                /**Creates new flow and inserts it in the list.**/
                f.Last=f.First;
                f.dPkts=1;
                ++sizes[i];
                if(sizes[i]>capacities[i]){
                    newcapacity=capacities[i]*2;
                    h[i]=(hashElement*)realloc(h[i],newcapacity*sizeof(hashElement));
                    memset(h[i]+sizes[i]-1,0,capacities[i]*sizeof(hashElement));
                    capacities[i]=newcapacity;
                }
                h[i][sizes[i]-1]=f;
                ++activeFlows;
                if(activeFlows==maxActiveFlows)
                    checkExpiration(-1,l,NULL);
            }
        }
    }

    /**
     * Checks if some flow is expired (max for n flows). Start from the last flow checked.
     * \return A vector of expired flows.
     * \param n Maximum number of flow to check.
     * \param l A pointer to the list where to add the expired flows.
     * \param now A pointer to current time value.
     */
    void checkExpiration(int n, ff::squeue<hashElement>* l, time_t* now){
        if(n==0) return;
        uint nodeChecked=0,lineChecked=0,limit,newcapacity;
        /**If n<=-1 checks all flows in the hash table.**/
        if(n<=-1)
          limit=std::numeric_limits<uint>::max();
        else
          limit=n;
        hashElement *line=h[lasti];
        while(nodeChecked<limit && lineChecked<=size){
            if(lastj!=sizes[lasti]){
                ++nodeChecked;
                /**If the flow is expired, adds the flow to the vector.**/
                if(isExpired(line[lastj],idle,lifetime,now)){
                    l->push_back(line[lastj]);
                    --activeFlows;
                    std::swap(line[lastj],line[sizes[lasti]-1]);
                    memset(h[lasti]+sizes[lasti]-1,0,sizeof(hashElement));
                    --sizes[lasti];
                    newcapacity=capacities[lasti]/2;
                    if(sizes[lasti]<newcapacity && newcapacity>=10){
                        h[lasti]=(hashElement*) realloc(h[lasti],newcapacity*sizeof(hashElement));
                        line=h[lasti];
                        capacities[lasti]=newcapacity;
                    }
                }else
                    ++lastj;
            /**If the end of the row is arrived, checks the next row.**/
            }else{
                ++lineChecked;
                lasti=(lasti+1) % size;
                line=h[lasti];
                lastj=0;
            }
        }
    }

    /**
     * Flush the hash table and insert the flows in the queue.
     * \param flowsToExport The queue in which the flows will be inserted.
     */

    inline void flush(ff::squeue<hashElement> *flowsToExport){
        checkExpiration(-1,flowsToExport,NULL);
    }

    inline uint getActiveFlows(){
        return activeFlows;
    }
};


/**
 * Computes the hash function on a flow.
 * \param f The flow.
 * \param mod Size of the hash table (Size(hashT1)+Size(hashT2)+....+Size(hashTn))
 * \return Hash(f)%Mod
 */
inline uint hashFun(const hashElement& f,const uint mod){
    return (f.dstaddr+f.srcaddr+f.prot+f.srcport+f.dstport+f.tos)%mod;
}


#endif /* HASHTABLE_HPP_ */
