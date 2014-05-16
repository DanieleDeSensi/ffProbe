/*
 * task.cpp
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
 * This file contains the definition of the task passed by the stages of the pipeline.
 */

 #include "task.hpp"


 /**
  * Constructor of the task.
  * \param numWorkers Number of workers of the pipeline.
  */
 Task::Task(uint numWorkers):numWorkers(numWorkers),eof(false){
     flowsToAdd=new ff::squeue<hashElement>*[numWorkers];
     for(uint i=0; i<numWorkers; i++)
         flowsToAdd[i]=new ff::squeue<hashElement>;
     flowsToExport=new ff::squeue<hashElement>;
 }

 /**
  * Denstructor of the task.
  */
 Task::~Task(){
     if(flowsToExport!=NULL) delete flowsToExport;
     if(flowsToAdd!=NULL){
         for(uint i=0; i<numWorkers; i++)
             delete flowsToAdd[i];
         delete[] flowsToAdd;
     }
 }

/**
 * Sets the timestamp of the task.
 * \param t The timestamp.
 */
void Task::setTimestamp(time_t t){
    timestamp=t;
}

/**
 * Returns the timestamp of the task.
 * \return The timestamp of the task.
 */
time_t Task::getTimestamp(){
    return timestamp;
}

/**
 * Adds an hashElement to the list of flows to export.
 * \param h The hashElement.
 */
void Task::addFlowToExport(hashElement& h){
    flowsToExport->push_back(h);
}

/**
 * Returns a pointer to the list of flows to export.
 * \return A pointer to the list of flows to export.
 */
ff::squeue<hashElement>* Task::getFlowsToExport(){
    return flowsToExport;
}

/**
 * Returns a pointer to the list of the flows to add.
 * \return A pointer to the list of the flows to add.
 */
ff::squeue<hashElement>* Task::getFlowsToAdd(const int i){
    return flowsToAdd[i];
}

/**
 * Adds the hashElement h for the i-th worker.
 * \param h The hashElement to add.
 * \param i The worker that have to add the flow.
 */
void Task::setFlowToAdd(hashElement& h, const int i){
    flowsToAdd[i]->push_back(h);
}

/**Sets EOF. **/
void Task::setEof(){eof=true;}

/**Resets EOF.**/
void Task::resetEof(){eof=false;}

/**
 * Returns true if EOF of a .pcap file is arrived.
 * \return True if EOF is arrived, otherwise returns false.
 */
bool Task::isEof(){return eof;}

/**
 * Returns the number of workers.
 * \return The number of workers.
 */
int Task::getNumWorkers(){
    return numWorkers;
}
