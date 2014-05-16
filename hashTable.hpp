/*
 * hashTable.hpp
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
 * Implementation of the hash table used by the workers to insert the flows.
 */

#ifndef HASHTABLE_HPP_
#define HASHTABLE_HPP_
#include <cassert>
#include <limits>
#include <algorithm>
#include <ff/squeue.hpp>

#include "flow.hpp"

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
    Hash(uint d, uint maxActiveFlows, uint idle, uint lifetime);

    /**
     * Destructor of the hash table.
     */
    ~Hash();

    /**
     * Adds (or updates) some flows. If the hash table has the max number of active flows, adds to l a flow and remove it from
     * the hash table.
     * \param flowsToAdd A list of flows to add.
     * \param l A pointer to a list of expired flows.
     */
    void updateFlows(ff::squeue<hashElement>* flowsToAdd, ff::squeue<hashElement>* l);

    /**
     * Checks if some flow is expired (max for n flows). Start from the last flow checked.
     * \return A vector of expired flows.
     * \param n Maximum number of flow to check.
     * \param l A pointer to the list where to add the expired flows.
     * \param now A pointer to current time value.
     */
    void checkExpiration(int n, ff::squeue<hashElement>* l, time_t* now);

    /**
     * Flush the hash table and insert the flows in the queue.
     * \param flowsToExport The queue in which the flows will be inserted.
     */

    void flush(ff::squeue<hashElement> *flowsToExport);

    uint getActiveFlows();
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
