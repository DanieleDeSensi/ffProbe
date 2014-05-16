/*
 * utils.hpp
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

#ifndef UTILS_HPP_
#define UTILS_HPP_

typedef unsigned int uint;

#include <math.h>

/**
 * Create the array with the identifiers of the cores on which the threads must be mapped.
 * The elements from 0 to readers-1 will be the identifiers of the cores on which the readers must be mapped.
 * The elements from readers to readers+workers-1 will be the identifiers of the cores on which the workers must be mapped.
 * The last element of the array will be the identifier of the core on which the exporter must be mapped.
 */
bool contains(std::vector<std::pair<uint,uint> > &v, std::pair<uint,uint> &element);

/**
 * Extract infos about the displacement of the cores on the chips of the machine.
 * \param v This vector will be filled with the identifiers of the cores. If we have n cores per chip the vector
 *          will be divided in blocks of n elements. Each block will represents the identifiers of the core on a chip.
 * Returns the number chips on the machine or 0 on error.
 */
uint captureCpuInfos(std::vector<uint> &processors_to_use);

void generateMapping(uint* cores, uint numThreads, uint chip);

/**Generate suggestions about a possible reduction/increase of the parallelism degree.**/
void generateSuggestions(float *workers_latencies, uint workers, float reader_latency, float exporter_latency, uint indipendent_exporter, uint readers=1);

#endif
