// Netify Agent Test Suite
// Copyright (C) 2024 eGloo Incorporated
// <http://www.egloo.ca>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <algorithm>
#include <iostream>

#include "nd-ndpi.hpp"
#include "nd-protos.hpp"

using namespace std;

int main(int argc, char *argv[]) {
    int rc = 0;
    char proto_name[64];

    cout << "Testing Netify Agent Protocols..." << endl;

    ndpi_global_init();
    ndpi_detection_module_struct *ndpi = nd_ndpi_init();

    cout << endl
         << "nDPI protocol count: " << NDPI_LAST_IMPLEMENTED_PROTOCOL
         << endl;
    cout << "Netify Agent protocol count: "
         << ndProto::nDPI::Protos.size() << endl
         << endl;

    for (uint16_t id = 0; id < NDPI_LAST_IMPLEMENTED_PROTOCOL; id++)
    {
        auto it = ndProto::nDPI::Protos.find(id);
        if (find(ndProto::nDPI::Disabled.begin(),
              ndProto::nDPI::Disabled.end(),
              id) != ndProto::nDPI::Disabled.end())
            continue;
        if (find(ndProto::nDPI::Free.begin(),
              ndProto::nDPI::Free.end(),
              id) != ndProto::nDPI::Free.end())
            continue;

        if (it != ndProto::nDPI::Protos.end()) continue;

        ndpi_protocol proto = { id, 0 };
        ndpi_protocol2name(ndpi, proto, proto_name,
          sizeof(proto_name));

        rc = 1;
        cout << "ID# " << id << " (" << proto_name << ")" << endl;
    }

    if (rc != 0) cout << endl;
    cout << "Test result: " << ((rc == 0) ? "PASS" : "FAIL") << endl
         << endl;

    return rc;
}
