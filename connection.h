#include <boost/python.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>

#include <sstream>
#include <string>
#include <sys/time.h>
#include <thread>
#include <vector>

#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/count.hpp>
#include <boost/accumulators/statistics/max.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/statistics/min.hpp>
#include <boost/accumulators/statistics/sum.hpp>
#include <boost/accumulators/statistics/variance.hpp>

#include "protocols/icmp4.h"
#include "protocols/icmp6.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"

/* For convenience. */
namespace bp = boost::python;

using namespace snort;
using namespace boost::accumulators;

typedef accumulator_set<int64_t, features<tag::count, tag::sum, tag::min,
                                          tag::max, tag::mean, tag::variance>>
    intAcc;
typedef accumulator_set<double, features<tag::count, tag::sum, tag::min,
                                         tag::max, tag::mean, tag::variance>>
    doubleAcc;

class Connection {
public:
  Connection(Packet *p, std::string id);

  /* Method used to update a connection based on the packet's information. */
  void add_packet(Packet *p);
  /* Method used to initialize the flags counter. */
  void init_flags();
  /* Method used to initialize most of this class' variables/parameters. */
  void init_parameters();

  //-------------------------------------------------------------------------
  // UPDATING EXISTING FLOWS
  //-------------------------------------------------------------------------
  /* Method used to update the flags_counter (TCP-only). */
  void update_flags_counter(Packet *p);
  /* Method used to update the bulk flow in the forward direction. */
  void update_forward_bulk(Packet *p, int64_t op_bulk_last_timestamp);
  /* Method used to update the bulk flow in the backward direction. */
  void update_backward_bulk(Packet *p, uint32_t op_bulk_last_timestamp);
  /* Method used to update the bulk flow. */
  void update_flow_bulk(Packet *p);
  /* Method used to update both active and idle time of the flow. */
  void update_active_idle_time(int64_t current_time, int64_t threshold);
  /* Method used to update subflows. */
  void update_subflows(Packet *p);

  //-------------------------------------------------------------------------
  // GETTERS
  //-------------------------------------------------------------------------
  std::string get_flowid() { return flow_id; }
  int64_t get_flowfirstseen() { return flow_first_seen; }
  int64_t get_flowlastseen() { return flow_last_seen; }
  uint32_t get_fbulkstatecount() { return f_bulk_state_count; }
  uint32_t get_fbulktotalsize() { return f_bulk_total_size; }
  uint32_t get_fbulkpktcount() { return f_bulk_packet_count; }
  int64_t get_fbulkduration() { return f_bulk_duration; }
  uint32_t get_bbulkstatecount() { return b_bulk_state_count; }
  uint32_t get_bbulktotalsize() { return b_bulk_total_size; }
  uint32_t get_bbulkpktcount() { return b_bulk_packet_count; }
  int64_t get_bbulkduration() { return b_bulk_duration; }

  double get_flowbytespersec() {
    int64_t duration = flow_last_seen - flow_first_seen;

    if (duration > 0) {
      return ((double)(forward_bytes + backward_bytes)) /
             ((double)duration / 1000000);
    } else {
      return 0;
    }
  }
  double get_flowpktspersec() {
    int64_t duration = flow_last_seen - flow_first_seen;
    uint32_t packet_count = forward_count + backward_count;

    if (duration > 0) {
      return ((double)packet_count) / ((double)duration / 1000000);
    } else {
      return 0;
    }
  }

  double get_fpktspersec() {
    int64_t duration = flow_last_seen - flow_first_seen;

    if (duration > 0) {
      return ((double)forward_count) / ((double)duration / 1000000);
    } else {
      return 0;
    }
  }

  double get_bpktspersec() {
    int64_t duration = flow_last_seen - flow_first_seen;

    if (duration > 0) {
      return ((double)backward_count) / ((double)duration / 1000000);
    } else {
      return 0;
    }
  }

  double get_downupratio() {
    if (forward_count > 0) {
      return ((double)backward_count / (double)forward_count);
    } else {
      return 0;
    }
  }

  double get_avgpktsize() {
    uint32_t packet_count = forward_count + backward_count;
    if (packet_count > 0) {
      return (sum(flow_length) / (double)packet_count);
    } else {
      return 0;
    }
  }

  double get_favgsegmentsize() {
    if (forward_count > 0) {
      return (sum(forward_pkt) / (double)forward_count);
    } else {
      return 0;
    }
  }

  double get_bavgsegmentsize() {
    if (backward_count > 0) {
      return (sum(backward_pkt) / (double)backward_count);
    } else {
      return 0;
    }
  }

  double get_fsubflowbytes() {
    if (sf_count > 0) {
      return ((double)forward_bytes / (double)sf_count);
    } else {
      return 0;
    }
  }

  double get_fsubflowpkts() {
    if (sf_count > 0) {
      return ((double)forward_count / (double)sf_count);
    } else {
      return 0;
    }
  }

  double get_bsubflowbytes() {
    if (sf_count > 0) {
      return ((double)backward_bytes / (double)sf_count);
    } else {
      return 0;
    }
  }

  double get_bsubflowpkts() {
    if (sf_count > 0) {
      return ((double)backward_count / (double)sf_count);
    } else {
      return 0;
    }
  }

  double get_fbulkduration_seconds() {
    return f_bulk_duration / (double)1000000;
  }

  uint32_t get_favgbytesperbulk() {
    if (get_fbulkstatecount() != 0) {
      return (get_fbulktotalsize() / get_fbulkstatecount());
    } else {
      return 0;
    }
  }

  uint32_t get_favgpktsperbulk() {
    if (get_fbulkstatecount() != 0) {
      return (get_fbulkpktcount() / get_fbulkstatecount());
    } else {
      return 0;
    }
  }

  uint32_t get_favgbulkrate() {
    if (get_fbulkduration() != 0) {
      return (uint32_t)(get_fbulktotalsize() / get_fbulkduration_seconds());
    } else {
      return 0;
    }
  }
  double get_bbulkduration_seconds() {
    return b_bulk_duration / (double)1000000;
  }

  uint32_t get_bavgbytesperbulk() {
    if (get_bbulkstatecount() != 0) {
      return (get_bbulktotalsize() / get_bbulkstatecount());
    } else {
      return 0;
    }
  }

  uint32_t get_bavgpktsperbulk() {
    if (get_bbulkstatecount() != 0) {
      return (get_bbulkpktcount() / get_bbulkstatecount());
    } else {
      return 0;
    }
  }

  uint32_t get_bavgbulkrate() {
    if (get_bbulkduration() != 0) {
      return (uint32_t)(get_bbulktotalsize() / get_bbulkduration_seconds());
    } else {
      return 0;
    }
  }

  //-------------------------------------------------------------------------
  // Feature Vector Operations
  //-------------------------------------------------------------------------
  std::vector<double> get_feature_vector();
  void print_feature_vector(std::vector<double> feature_vector);

private:
  std::string flow_id;

  SfIpString client_ip;
  SfIpString server_ip;
  uint16_t client_port;
  uint16_t server_port;

  uint8_t protocol;

  uint32_t forward_count;
  uint32_t backward_count;

  int64_t flow_first_seen;
  int64_t flow_last_seen;

  int64_t forward_last_seen;
  int64_t backward_last_seen;

  int64_t start_active_time;
  int64_t end_active_time;

  std::map<std::string, uint32_t> flags_counter;

  uint32_t forward_PSH;
  uint32_t forward_URG;
  uint32_t backward_PSH;
  uint32_t backward_URG;

  uint32_t forward_bytes;
  uint32_t forward_hbytes;
  uint32_t backward_bytes;
  uint32_t backward_hbytes;

  uint32_t act_data_pkt_forward;

  uint32_t min_seg_size_forward;

  uint32_t init_win_bytes_forward;
  uint32_t init_win_bytes_backward;

  intAcc flow_iat;
  intAcc forward_iat;
  intAcc backward_iat;

  intAcc flow_idle;
  intAcc flow_active;

  doubleAcc flow_length;
  doubleAcc forward_pkt;
  doubleAcc backward_pkt;

  /* Subflows */
  uint32_t sf_count = 0;
  int64_t sf_ac_helper =
      -1; /* This is initialized as -1, so it has to be int32_t. */
  int64_t sf_last_packet_timestamp =
      -1; /* This is initialized as -1, so it has to be int32_t. */

  /* Forward bulk flow. */
  int64_t f_bulk_duration = 0;
  uint32_t f_bulk_total_size = 0;
  uint32_t f_bulk_state_count = 0;
  uint32_t f_bulk_packet_count = 0;
  uint32_t f_bulk_size_helper = 0;
  int64_t f_bulk_start_helper = 0;
  uint32_t f_bulk_packet_count_helper = 0;
  int64_t f_bulk_last_timestamp = 0;

  /* Backward bulk flow. */
  int64_t b_bulk_duration = 0;
  uint32_t b_bulk_total_size = 0;
  uint32_t b_bulk_state_count = 0;
  uint32_t b_bulk_packet_count = 0;
  uint32_t b_bulk_size_helper = 0;
  int64_t b_bulk_start_helper = 0;
  uint32_t b_bulk_packet_count_helper = 0;
  int64_t b_bulk_last_timestamp = 0;
};

struct TimeoutedConnections {
  std::vector<std::string> id;
  std::vector<Connection> connections;
  std::vector<std::vector<double>> features;
};

//-------------------------------------------------------------------------
// Utility FUNCTIONS MOVE THESE!!!
//-------------------------------------------------------------------------

inline int64_t get_time_in_microseconds() {
  struct timeval timestamp;
  gettimeofday(&timestamp, NULL);
  return timestamp.tv_sec * (int)1e6 + timestamp.tv_usec;
}

inline int64_t get_time_in_microseconds(time_t tvsec, suseconds_t tvusec) {
  return tvsec * (int)1e6 + tvusec;
}
