// Netify Agent Risks-to-CSV
// Copyright (C) 2024 eGloo Incorporated
// <http://www.egloo.ca>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>

#include "nd-ndpi.hpp"
#include "nd-risks.hpp"

using namespace std;

int main(int argc, char* argv[]) {
    ndpi_global_init();

    cout << "Netify ID,nDPI ID,Risk,Severity,Score,Client "
            "Score,Server Score"
         << endl;

    for (uint16_t id = 1; id < NDPI_MAX_RISK; id++) {
        auto it = ndRisk::nDPI::Risks.find(id);
        if (it == ndRisk::nDPI::Risks.end()) continue;

        ndpi_risk_enum rid = (ndpi_risk_enum)id;
        ndpi_risk risk = (uint64_t)2 << (rid - 1);

        ndpi_risk_info const* const risk_info =
          ndpi_risk2severity(rid);
        if (risk_info == nullptr) continue;

        const char* desc = ndpi_risk2str(rid);
        const char* severity = ndpi_severity2str(risk_info->severity);

        uint16_t client_score, server_score;
        uint16_t score = ndpi_risk2score(risk,
          &client_score, &server_score);

        cout << id << "," << rid << "," << desc << ","
             << severity << "," << score << ","
             << client_score << "," << server_score << endl;
    }

    return 0;
}
