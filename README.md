Introduction
=======

ffProbe is a new pipelined parallel implementation of a NetFlow probe built
on top of FastFlow, a parallel programming framework for multicore platforms based
on non-blocking lock-free/fence-free synchronization mechanisms.
Thanks to an efficient design, ffProbe is able to scale with the number of cores used
and to process up to 10 Million Packets per Second using a commodity 8-cores processor.

For more information about ffProbe implementation, result and comparison with other open
source solutions, please check the paper "Network Monitoring on Multicores with Algorithmic Skeletons".

Dependencies
=======
To let ffProbe work, [PF_RING](http://www.ntop.org/products/pf_ring/) needs to be installed on the machine.

Usage
=======




Parameters
=======
```-i <captureInterface>```: Interface name from which packets are captured. You can also specify more than one interface separating them by an underscore (e.g. -i eth1_eth2_..._ethn). In this case you have also to specify -r n

```--sequential```: Executes the probe sequentially.

```-d <idleTimeout>```: It specifies the maximum (seconds) flow idle lifetime [default 30].

```-l <lifetimeTimeout>```: It specifies the maximum (seconds) flow lifetime [default 120].

```-q <queueTimeout>```: It specifies after how many seconds expired flows (queued before delivery) are emitted [default 30].

```-r <readers>```: It specifies how many reader threads read from different interfaces [default 1]. If you want to use more than one reader you have to recompile ffProbe with -DMULTIPLE_READERS.
		
```-w <workers>```: It specifies how many threads manage the hash table [default 1]. ```hashSize % (workers)``` must be equals to 0.

```-e <exporters>```: It specifies if the exporter is executed by an indipendent thread (1) or if it's executed by the same thread of one of the workers (0) [default 1].

```-j <cores>``` or ```--cores <cores>```: It specifies the identifiers of the cores on which the stages of the pipeline should be mapped [default 0]. The cores identifiers must be separated by an underscore (e.g. ```0_1_2_3```). The stages of the pipeline will be mapped in the same order.

```-u <socket>```: It specifies the identifier of the processor socket on which the process will run [default 0]. 
		
```-s <hashSize>```: It specifies the size of the hash table where the flows are stored [default 32762]. ```hashSize % (workers)``` must be equals to 0, moreover ```hashSize``` must not be a power of 2.

```-m <maxActiveFlows>```: Limit the number of active flows for one worker. This is useful if you want to limit the memory used by ffProbe [default 3000000].

```-x <cnt>```: Cnt is the maximum number of packets to process before returning from reading, but is not a minimum number. If less than cnt packets are present, only those packets will be processed. If no packets are presents, read returns immediately. A  value of -1 means "process packets until there is at least one packet on the buffer". This can be dangerous because if the packets rate is very high the program will always find packets in the buffer and so can fill the memory. A value of -1 when reading a live capture causes all the packets in the file to be processed [default 10000].

```-f <outputFile>```: Print the flows in textual format on a file.

```-z <flowsPerTaskCheck>```: Number of flows to check for expiration after the arrival of a task to a worker. (-1 is all) [default 200].

```-c <collector>``` or ```--collector <collector>```: Host of the Netflow collector [default 127.0.0.1].

```-p <port>``` or ```--port <port>```: Port of the Netflow collector [default 2055].

```-y <minFlowSize>```: Minimum TCP flow size (in bytes). If a TCP flow is shorter than the specified size the flow  is not emitted. 0 is unlimited [default unlimited].

```-n``` or ```--nopromisc```: Disables the 'Promiscuous' mode on the interface.

```-h```: Prints the help page.


