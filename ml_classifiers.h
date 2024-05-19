#include <cstdlib>

#include <string>
#include <sys/time.h>
#include <vector>

#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/count.hpp>
#include <boost/accumulators/statistics/max.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/statistics/min.hpp>
#include <boost/accumulators/statistics/sum.hpp>
#include <boost/accumulators/statistics/variance.hpp>

#include "protocols/packet.h"

using namespace snort;
using namespace boost::accumulators;

// Core Plugin Functions
std::vector<std::string> get_id_candidates(Packet *p);
void verify_timeouts();
void check_connections(Packet *p);

// ML Classification Functions
void createOutputStream();
void transformOutputStream();
void printClassifiedConnections(std::string attackName);
void classify_connections();
