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

class MLClassifiers : public Inspector {
private:
public:
  MLClassifiers();

  bool configure(SnortConfig *) override;
  void show(const SnortConfig *) const override;
  void eval(Packet *) override;

  // Core Plugin Functions
  std::string caclulate_flowID(Packet *p);
  void detect_expired_connections(Packet *p);
  void classify_expired_connections();
  void delete_expired_connections();
  void checkConnectionsScheduler();
};

// Utility Functions
void createOutputStream();
void transformOutputStream();
void printClassifiedConnections(std::string attackName);
