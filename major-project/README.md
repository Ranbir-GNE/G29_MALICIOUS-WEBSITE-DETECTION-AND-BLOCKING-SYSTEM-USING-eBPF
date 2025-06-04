# Netify Agent
https://netify.ai

Copyright ©2015-2024 eGloo Incorporated ([www.egloo.ca](https://www.egloo.ca))

CI Status: [![pipeline status](https://gitlab.com/netify.ai/public/netify-agent/badges/master/pipeline.svg)](https://gitlab.com/netify.ai/public/netify-agent/-/commits/master)

## Network Intelligence - Simplified
The [Netify Agent](https://www.netify.ai/) is a deep-packet inspection server.  The Agent is built on top of [nDPI](http://www.ntop.org/products/deep-packet-inspection/ndpi/) (formerly OpenDPI) to detect network protocols and applications.  Detections can be saved locally, served over a UNIX or TCP socket, and/or "pushed" (via HTTP POSTs) to a remote third-party server.  Flow metadata, network statistics, and detection classifications are stored using JSON encoding.

Optionally, the Netify Agent can be coupled with a [Netify Cloud](https://www.netify.ai/) subscription for further cloud processing, historical storage, machine-learning analysis, event notifications, device detection/identification, along with the option (on supported platforms) to take an active role in policing/bandwidth-shaping specific network protocols and applications.

## Download Packages
Supported platforms with installation instructions can be found [here](https://www.netify.ai/get-netify).

Alternatively, binary packages are available for several common distributions.  Visit the [downloads area](https://download.netify.ai/) of the Netify website.

## Download Source

Full [source archives](https://download.netify.ai/source/) are available from the Netify website.

Optionally, the source can be cloned with [git](https://gitlab.com/netify.ai/public/netify-agent.git).  When cloning the source tree, include the `--recursive` option to clone the required sub-modules.

### Build Requirements
Netify requires the following third-party packages:
- libcurl
- libpcap
- zlib
- [Linux] libmnl
- [Linux] libnetfilter-conntrack

Optional:
- google-perftools/gperftools/libtcmalloc (will use bundled version when not available)

### Configuring/Building From Source
Read the appropriate documentation in the doc directory, prefixed with: `BUILD-*`

Generally the process is:
```sh
./autogen.sh
./configure
make
```

## Online Documentation
Further user and developer documentation can be found [here](https://www.netify.ai/resources).  The project Wiki is available [here](https://gitlab.com/netify.ai/public/netify-agent/-/wikis/home).

## License
The Netify Agent is dual-licensed under commercial and open source licenses. The commercial license gives you the full rights to create and distribute software on your own terms without any open source license obligations.

The Netify Agent is also available under GPL and LGPL open source licenses.  The open source licensing is ideal for student/academic purposes, hobby projects, internal research projects, or other projects where all open source license obligations can be met.

The Netify Agent includes the following libraries:
- nDPI - LGPL license
- inih -  3-Clause BSD license
- [optional] gperftools - Google license
