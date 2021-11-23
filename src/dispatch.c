#include "dispatch.h"
#include <pcap.h>
#include "analysis.h"

void dispatch(unsigned char *userdata, struct pcap_pkthdr *header,
              const unsigned char *packet) {
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  analyse(header, packet, (int)userdata);
}
