#ifndef _OFFLINE_PADO_PARTY_H_
#define _OFFLINE_PADO_PARTY_H_
#include "emp-tool/emp-tool.h"
using namespace emp;

/* Define the offline party */
class OfflinePADOParty : public ProtocolExecution {
   public:
    OfflinePADOParty(int party) : ProtocolExecution(party) {}
};
#endif