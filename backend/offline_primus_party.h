#ifndef _OFFLINE_PRIMUS_PARTY_H_
#define _OFFLINE_PRIMUS_PARTY_H_
#include "emp-tool/emp-tool.h"
using namespace emp;

/* Define the offline party */
class OfflinePrimusParty : public ProtocolExecution {
   public:
    OfflinePrimusParty(int party) : ProtocolExecution(party) {}
};
#endif
