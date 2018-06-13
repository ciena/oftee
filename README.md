# OpenFlow [PACKET_IN] Tee

This is a utility filter that sits between and OpenFlow device and the
OpenFlow controller. This filter bidirectionally passes, as is, all
traffic between the device and the controller. Additionally, this filter
can be configured to *tee* OpenFlow *packet in* messages to third party
applications via `Kafka` (future) and `REST`.

The purpose of this utility filter is to allow the development if SDN
applications that execute outside the SDN controller processes, i.e,
that don't have to be written for a specific SDN controller such as
`ONOS` or `ODL`.

## SDN Application Initialization
To utilize the OpenFlow tee the *external* SDN application or operator
must perform some initialization so that the OpenFlow device does a
packet in to the controller on the desired packets and the *tee* forwards
the desired packets to the external SDN application.

![Application Initialization](app_init.png)

## SDN Application Behavior
While the SDN application receives packet in packets from the OpenFlow
Tee, if should use the controller's API to influence an open flow device
or to emit a packet back into the open flow network.

![Application Behavior](app_behavior.png)
It is possible and expected for the SDN to communicate over the network
to other services or applications outside the OpenFlow network.
