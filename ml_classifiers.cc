//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// ml_classifier.cc author Luan Utimura <luan.utimura@gmail.com>

#include "ml_classifiers.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include <mutex>
#include <ostream>

using namespace snort;

static const char *s_name = "ml_classifiers";
static const char *s_help = "machine learning classifiers";

static THREAD_LOCAL ProfileStats ml_PerfStats;
static THREAD_LOCAL SimpleStats ml_stats;
std::mutex ml_mutex;

/* Selected Machine Learning Technique. */
std::string attack_type;

/* Map of current active connections.*/
std::map<std::string, Connection> connections;
std::map<std::string, Connection>::iterator connections_it;

TimeoutedConnections t_connections;
//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class MLClassifiers : public Inspector {
public:
  MLClassifiers();

  bool configure(SnortConfig *) override;
  void show(const SnortConfig *) const override;
  void eval(Packet *) override;
};

MLClassifiers::MLClassifiers() {
  LogMessage("[*] MLClassifiers::MLClassifiers()\n");
}

bool MLClassifiers::configure(SnortConfig *) {
  std::thread verify_thread(verify_timeouts);
  verify_thread.detach();
  return true;
}

void MLClassifiers::show(const SnortConfig *) const {
  LogMessage("[*] MLClassifers::show\n");
}

void MLClassifiers::eval(Packet *p) {
  std::lock_guard<std::mutex> lock(ml_mutex);
  if ((p->is_tcp() || p->is_udp() || p->is_icmp()) && p->flow) {
    std::vector<std::string> id_candidates = get_id_candidates(p);

    /* Attempts to find an existent connection with the flow_id equals to
     * id_candidates[0]. */
    connections_it = connections.find(id_candidates[0]);

    /* If it couldn't find an existent connection with the above flow_id, it
       attempts again with the flow_id equals to id_candidates[1] .*/
    if (connections_it == connections.end()) {
      connections_it = connections.find(id_candidates[1]);
    }

    /* Finally, checks if any connection was found. */
    if (connections_it != connections.end()) {
      /* Found it! */

      /* Adds the packet's information to the connection. */
      connections_it->second.add_packet(p);
    } else {
      /* Couldn't find it... */

      /* Creates a new connection and inserts it in the connections list. */
      Connection newConnection(p, id_candidates[0]);
      connections.insert(
          std::pair<std::string, Connection>(id_candidates[0], newConnection));
    }
  }
  ++ml_stats.total_packets;
}
//-------------------------------------------------------------------------
// Machine Learning Classification and Alerts
//-------------------------------------------------------------------------

void createOutputStream() {
  std::ofstream outputFile;
  outputFile.open(
      "/home/angaja/privateRepo/ml_classifiers/tmp/timeouted_connections.txt",
      std::ios_base::trunc);

  for (int i = 0; i < t_connections.id.size(); i++) {
    outputFile << std::fixed << std::setprecision(9);

    for (int j = 0; j < 78; j++) {
      outputFile << t_connections.features[i][j];

      if (j == 77)
        outputFile << std::scientific << "\n";
      else
        outputFile << " ";
    }
  }
  outputFile.close();
}

void transformOutputStream() {
  std::string py_cmd2 =
      "python "
      "/home/angaja/privateRepo/ml_classifiers/python-utility/csvTransforer.py";
  system(py_cmd2.c_str());
}

void printClassifiedConnections(std::string attackName) {
  std::ifstream inputFile("/home/angaja/privateRepo/ml_classifiers/tmp/"
                          "timeouted_connections_results" +
                          attackName + ".txt");

  if (inputFile.is_open()) {
    std::string line;
    uint32_t index = 0;

    while (std::getline(inputFile, line)) {
      float predictedValue;
      std::istringstream iss(line);
      iss >> predictedValue;

      if (predictedValue >= 0.90f) {
        std::cout << "[-] ML-Classified: " << t_connections.id[index]
                  << "\tResult: " << "Attack (" << predictedValue << ") - "
                  << attackName << std::endl;
      }

      index++;
    }

    inputFile.close();
  }
}

void classify_connections() {
  createOutputStream();
  transformOutputStream();

  std::vector<std::thread> classificationThreads;
  std::string attackTypes[] = {"ddos", "bruteforce", "botnet", "sql",
                               "infiltration"};

  for (const std::string &attack : attackTypes) {
    classificationThreads.emplace_back([attack]() {
      std::cout << "Debug: Calling " + attack + " Classifier" << std::endl;

      std::string py_cmd = "python "
                           "/home/angaja/privateRepo/ml_classifiers/ml_models/"
                           "IntrusionModelNetworkPredictor.py " +
                           attack;
      system(py_cmd.c_str());

      std::cout << "Debug: Continuing execution after calling " + attack +
                       " Classifier"
                << std::endl;

      printClassifiedConnections(attack);
    });
  }

  for (auto &thread : classificationThreads) {
    if (thread.joinable()) {
      thread.join();
    }
  }

  t_connections.id.clear();
  t_connections.connections.clear();
  t_connections.features.clear();
}
//-------------------------------------------------------------------------
// Utility FUNCTIONS MOVE THESE!!!
//-------------------------------------------------------------------------

int64_t get_time_in_microseconds() {
  struct timeval timestamp;
  gettimeofday(&timestamp, NULL);
  return timestamp.tv_sec * (int)1e6 + timestamp.tv_usec;
}

int64_t get_time_in_microseconds(time_t tvsec, suseconds_t tvusec) {
  return tvsec * (int)1e6 + tvusec;
}

//-------------------------------------------------------------------------
// Packet Inspection Core
//-------------------------------------------------------------------------
void verify_timeouts() {
  // Thread's run function. Runs every 20 sec.
  while (true) {
    std::cout << "[+] verify_timeouts (" << connections.size() << ")"
              << std::endl;

    check_connections(nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(20000));
  }
}

void check_connections(Packet *p) {
  // Checks for expired connections and classifies them
  ml_mutex.lock();
  std::map<std::string, Connection> active_connections = connections;
  ml_mutex.unlock();

  for (auto it = active_connections.begin(); it != active_connections.end();
       it++) {
    int64_t time_difference;

    if (p == nullptr) {
      time_difference =
          get_time_in_microseconds() - it->second.get_flowlastseen();
    } else {
      time_difference =
          get_time_in_microseconds(p->pkth->ts.tv_sec, p->pkth->ts.tv_usec) -
          it->second.get_flowlastseen();
    }

    /* Assuming a default timeout value of 120 sec. */
    if (time_difference > 120000000) {
      ml_mutex.lock();

      /* Iterator pointing to the soon-to-be timeouted connection. */
      std::map<std::string, Connection>::iterator t_it =
          connections.find(it->first);

      if (t_it != connections.end()) {
        /* Retrieves all the flow's information and puts them in a vector. */
        std::vector<double> feature_vector = t_it->second.get_feature_vector();

        /*
            Transfer the timeouted connection to a struct responsible for
            holding it's informations.
        */
        t_connections.id.push_back(t_it->second.get_flowid());
        t_connections.features.push_back(feature_vector);
        t_connections.connections.push_back(t_it->second);

        connections.erase(t_it);
      }
      ml_mutex.unlock();
    }
  }
  // If timeouted connections have been added in this iteration we need to
  // classify them
  if (t_connections.id.size() > 0) {
    classify_connections();
  }
}

std::vector<std::string> get_id_candidates(Packet *p) {
  std::vector<std::string> id_candidates;

  std::ostringstream iss, reversed_iss;

  if (p->is_tcp()) {
    iss << "TCP";
    reversed_iss << "TCP";
  } else if (p->is_udp()) {
    iss << "UDP";
    reversed_iss << "UDP";
  } else if (p->is_icmp()) {
    iss << "ICMP";
    reversed_iss << "ICMP";
  }

  SfIpString client_ip, server_ip;
  p->flow->client_ip.ntop(client_ip);
  p->flow->server_ip.ntop(server_ip);

  iss << "-" << client_ip << ":" << p->flow->client_port << "-" << server_ip
      << ":" << p->flow->server_port;
  reversed_iss << "-" << server_ip << ":" << p->flow->server_port << "-"
               << client_ip << ":" << p->flow->client_port;

  if (p->is_icmp()) {
    iss << "-" << p->ptrs.icmph->s_icmp_id;
    reversed_iss << "-" << p->ptrs.icmph->s_icmp_id;
  }

  id_candidates.push_back(iss.str());
  id_candidates.push_back(reversed_iss.str());

  return id_candidates;
}
//-------------------------------------------------------------------------
// module stuff - Based of example Inspector provided by CISCO/Snort
//-------------------------------------------------------------------------

static const Parameter ml_params[] = {
    {"key", Parameter::PT_SELECT,
     "ddos | sql | infiltration | botnet | bruteforce", "ddos",
     "machine learning classifier"},
    {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}};

class MLClassifiersModule : public Module {
public:
  MLClassifiersModule() : Module(s_name, s_help, ml_params) {}

  const PegInfo *get_pegs() const override { return simple_pegs; }

  PegCount *get_counts() const override { return (PegCount *)&ml_stats; }

  ProfileStats *get_profile() const override { return &ml_PerfStats; }

  bool set(const char *, Value &v, SnortConfig *) override;

  Usage get_usage() const override { return INSPECT; }
};

bool MLClassifiersModule::set(const char *, Value &v, SnortConfig *) {
  LogMessage("[*] MLClassifiersModule::set\n");
  LogMessage("[*] Key: ");
  LogMessage(v.get_string());
  LogMessage("\n");

  attack_type = v.get_string();
  std::cout << attack_type << std::endl;

  return true;
}

//-------------------------------------------------------------------------
// api stuff - Based of example Inspector provided by CISCO/Snort
//-------------------------------------------------------------------------

static Module *mod_ctor() { return new MLClassifiersModule; }

static void mod_dtor(Module *m) { delete m; }

static Inspector *ml_ctor(Module *m) {
  MLClassifiersModule *mod = (MLClassifiersModule *)m;
  return new MLClassifiers();
}

static void ml_dtor(Inspector *p) { delete p; }

static const InspectApi ml_api{
    {PT_INSPECTOR, sizeof(InspectApi), INSAPI_VERSION, 0, API_RESERVED,
     API_OPTIONS, s_name, s_help, mod_ctor, mod_dtor},
    IT_PACKET,
    PROTO_BIT__ALL,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ml_ctor,
    ml_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi *snort_plugins[] = {&ml_api.base, nullptr};

//-------------------------------------------------------------------------
// CONNECTION MEMBER FUNCTIONS MOVE THESE!!!
//-------------------------------------------------------------------------

Connection::Connection(Packet *p, std::string id) {
  bool setlog = false;
  if (setlog) {
    std::cout << "[Log-Packet] " << id << std::endl;
  }
  /* Initializes the flags_counter and other parameters. */
  init_flags();
  init_parameters();

  update_flow_bulk(p);
  update_subflows(p);

  /* Updates the flags_counter based on the packet's flags (TCP-only). */
  if (p->is_tcp()) {
    update_flags_counter(p);
  }

  flow_id = id;
  protocol = (uint8_t)p->ip_proto_next;

  /* The packet's timestamp in microseconds. */
  // uint32_t packet_timestamp = p->pkth->ts.tv_usec;
  int64_t packet_timestamp =
      get_time_in_microseconds(p->pkth->ts.tv_sec, p->pkth->ts.tv_usec);

  flow_first_seen = flow_last_seen = start_active_time = end_active_time =
      packet_timestamp;

  flow_length((double)p->dsize);

  p->flow->client_ip.ntop(client_ip);
  client_port = p->flow->client_port;

  p->flow->server_ip.ntop(server_ip);
  server_port = p->flow->server_port;

  /* Instead of comparing client_ip w/ packet_source,
     I'll use "p->is_from_client()".

      SfIpString packet_source;
      *(p->ptrs.ip_api.get_src())->ntop(packet_source);
  */

  /* Checks whether this packet is coming from the client or the server. */
  if (p->is_from_client()) {
    /* Coming from client (forward direction). */
    min_seg_size_forward = p->pkth->pktlen - p->dsize;

    if (p->is_tcp()) {
      init_win_bytes_forward = p->ptrs.tcph->win();

      if (p->ptrs.tcph->are_flags_set(TH_PUSH)) {
        forward_PSH += 1;
      }

      if (p->ptrs.tcph->are_flags_set(TH_URG)) {
        forward_URG += 1;
      }
    }

    /*
        Note: In CICFlowMeter's code, the authors
        update the flow_length one more time.
        (Does that makes any sense?)
        flow_length((double)p->dsize);
    */
    forward_pkt((double)p->dsize);
    forward_bytes += p->dsize;
    forward_hbytes += p->pkth->pktlen - p->dsize;

    forward_last_seen = packet_timestamp;
    forward_count += 1;

  } else {
    /* Coming from server (backward direction). */
    if (p->is_tcp()) {
      init_win_bytes_backward = p->ptrs.tcph->win();

      if (p->ptrs.tcph->are_flags_set(TH_PUSH)) {
        backward_PSH += 1;
      }

      if (p->ptrs.tcph->are_flags_set(TH_URG)) {
        backward_URG += 1;
      }
    }

    /*
        Note: In CICFlowMeter's code, the authors
        update the flow_length one more time.
        (Does that makes any sense?)
        flow_length((double)p->dsize);
    */
    backward_pkt((double)p->dsize);
    backward_bytes += p->dsize;
    backward_hbytes += p->pkth->pktlen - p->dsize;

    backward_last_seen = packet_timestamp;
    backward_count += 1;
  }
}

void Connection::add_packet(Packet *p) {
  // uint32_t packet_timestamp = p->pkth->ts.tv_usec;
  int64_t packet_timestamp =
      get_time_in_microseconds(p->pkth->ts.tv_sec, p->pkth->ts.tv_usec);

  /*
  For some reason, the CICFlowMeter's authors kept these
  three lines commented for a long time.
  */
  update_flow_bulk(p);
  update_subflows(p);

  if (p->is_tcp()) {
    update_flags_counter(p);
  }

  flow_length((double)p->dsize);

  if (p->is_from_client()) {
    if (p->dsize >= 1.0f) {
      act_data_pkt_forward += 1;
    }

    if (p->is_tcp()) {
      if (p->ptrs.tcph->are_flags_set(TH_PUSH)) {
        backward_PSH += 1;
      }

      if (p->ptrs.tcph->are_flags_set(TH_URG)) {
        backward_URG += 1;
      }
    }

    forward_pkt((double)p->dsize);
    forward_bytes += p->dsize;
    forward_hbytes += p->pkth->pktlen - p->dsize;

    forward_count += 1;

    if (forward_count > 1) {
      forward_iat(packet_timestamp - forward_last_seen);
    }

    forward_last_seen = packet_timestamp;
    min_seg_size_forward =
        std::min((p->pkth->pktlen - p->dsize), min_seg_size_forward);

  } else {
    if (p->is_tcp()) {
      init_win_bytes_backward = p->ptrs.tcph->win();

      if (p->ptrs.tcph->are_flags_set(TH_PUSH)) {
        backward_PSH += 1;
      }

      if (p->ptrs.tcph->are_flags_set(TH_URG)) {
        backward_URG += 1;
      }
    }

    backward_pkt((double)p->dsize);
    backward_bytes += p->dsize;
    backward_hbytes += p->pkth->pktlen - p->dsize;

    backward_count += 1;

    if (backward_count > 1) {
      backward_iat(packet_timestamp - backward_last_seen);
    }

    backward_last_seen = packet_timestamp;
  }

  flow_iat(packet_timestamp - flow_last_seen);
  flow_last_seen = packet_timestamp;
}

void Connection::init_flags() {
  flags_counter["FIN"] = 0;
  flags_counter["SYN"] = 0;
  flags_counter["RST"] = 0;
  flags_counter["PSH"] = 0;
  flags_counter["ACK"] = 0;
  flags_counter["URG"] = 0;
  flags_counter["CWR"] = 0;
  flags_counter["ECE"] = 0;
}

/* Method used to initialize most of this class' variables/parameters. */
void Connection::init_parameters() {
  forward_count = 0;
  backward_count = 0;

  flow_first_seen = 0;
  flow_last_seen = 0;

  forward_last_seen = 0;
  backward_last_seen = 0;

  forward_PSH = 0;
  forward_URG = 0;
  backward_PSH = 0;
  backward_URG = 0;

  forward_bytes = 0;
  forward_hbytes = 0;
  backward_bytes = 0;
  backward_hbytes = 0;

  start_active_time = 0;
  end_active_time = 0;

  act_data_pkt_forward = 0;
  min_seg_size_forward = 0;

  init_win_bytes_forward = 0;
  init_win_bytes_backward = 0;
}

void Connection::update_flags_counter(Packet *p) {
  const tcp::TCPHdr *tcpHeader = p->ptrs.tcph;

  if (tcpHeader->are_flags_set(TH_FIN)) {
    flags_counter["FIN"] += 1;
  }
  if (tcpHeader->are_flags_set(TH_SYN)) {
    flags_counter["SYN"] += 1;
  }
  if (tcpHeader->are_flags_set(TH_RST)) {
    flags_counter["RST"] += 1;
  }
  if (tcpHeader->are_flags_set(TH_PUSH)) {
    flags_counter["PSH"] += 1;
  }
  if (tcpHeader->are_flags_set(TH_ACK)) {
    flags_counter["ACK"] += 1;
  }
  if (tcpHeader->are_flags_set(TH_URG)) {
    flags_counter["URG"] += 1;
  }
  if (tcpHeader->are_flags_set(TH_CWR)) {
    flags_counter["CWR"] += 1;
  }
  if (tcpHeader->are_flags_set(TH_ECE)) {
    flags_counter["ECE"] += 1;
  }
}

void Connection::update_forward_bulk(Packet *p,
                                     int64_t op_bulk_last_timestamp) {
  uint32_t size = p->dsize;
  // uint32_t packet_timestamp = p->pkth->ts.tv_usec;
  int64_t packet_timestamp =
      get_time_in_microseconds(p->pkth->ts.tv_sec, p->pkth->ts.tv_usec);

  if (op_bulk_last_timestamp > f_bulk_start_helper)
    f_bulk_start_helper = 0;
  if (size <= 0)
    return;

  if (f_bulk_start_helper == 0) {
    f_bulk_size_helper = size;
    f_bulk_packet_count_helper = 1;
    f_bulk_start_helper = packet_timestamp;
    f_bulk_last_timestamp = packet_timestamp;
  } else {
    if (((packet_timestamp - f_bulk_last_timestamp) / (double)1000000) > 1) {
      f_bulk_size_helper = size;
      f_bulk_packet_count_helper = 1;
      f_bulk_start_helper = packet_timestamp;
      f_bulk_last_timestamp = packet_timestamp;
    } else {
      f_bulk_size_helper += size;
      f_bulk_packet_count_helper += 1;

      if (f_bulk_packet_count_helper == 4) {
        f_bulk_state_count += 1;
        f_bulk_packet_count += f_bulk_packet_count_helper;
        f_bulk_total_size += f_bulk_size_helper;
        f_bulk_duration += packet_timestamp - f_bulk_start_helper;
      } else if (f_bulk_packet_count_helper > 4) {
        f_bulk_packet_count += 1;
        f_bulk_total_size += size;
        f_bulk_duration += packet_timestamp - f_bulk_last_timestamp;
      }

      f_bulk_last_timestamp = packet_timestamp;
    }
  }
}
void Connection::update_backward_bulk(Packet *p,
                                      uint32_t op_bulk_last_timestamp) {
  uint32_t size = p->dsize;
  // uint32_t packet_timestamp = p->pkth->ts.tv_usec;
  int64_t packet_timestamp =
      get_time_in_microseconds(p->pkth->ts.tv_sec, p->pkth->ts.tv_usec);

  if (op_bulk_last_timestamp > b_bulk_start_helper)
    b_bulk_start_helper = 0;
  if (size <= 0)
    return;

  if (b_bulk_start_helper == 0) {
    b_bulk_size_helper = size;
    b_bulk_packet_count_helper = 1;
    b_bulk_start_helper = packet_timestamp;
    b_bulk_last_timestamp = packet_timestamp;
  } else {
    if (((packet_timestamp - b_bulk_last_timestamp) / (double)1000000) > 1) {
      b_bulk_size_helper = size;
      b_bulk_packet_count_helper = 1;
      b_bulk_start_helper = packet_timestamp;
      b_bulk_last_timestamp = packet_timestamp;
    } else {
      b_bulk_size_helper += size;
      b_bulk_packet_count_helper += 1;

      if (b_bulk_packet_count_helper == 4) {
        b_bulk_state_count += 1;
        b_bulk_packet_count += b_bulk_packet_count_helper;
        b_bulk_total_size += b_bulk_size_helper;
        b_bulk_duration += packet_timestamp - b_bulk_start_helper;
      } else if (b_bulk_packet_count_helper > 4) {
        b_bulk_packet_count += 1;
        b_bulk_total_size += size;
        b_bulk_duration += packet_timestamp - b_bulk_last_timestamp;
      }

      b_bulk_last_timestamp = packet_timestamp;
    }
  }
}
void Connection::update_flow_bulk(Packet *p) {
  /*
      SfIpString packet_source;
      *(p->ptrs.ip_api.get_src())->ntop(packet_source);
  */
  if (p->is_from_client()) {
    update_forward_bulk(p, b_bulk_last_timestamp);
  } else {
    update_backward_bulk(p, f_bulk_last_timestamp);
  }
}

void Connection::update_active_idle_time(int64_t current_time,
                                         int64_t threshold) {
  if ((current_time - end_active_time) > threshold) {
    if ((end_active_time - start_active_time) > 0) {
      flow_active(end_active_time - start_active_time);
    }

    flow_idle(current_time - end_active_time);
    start_active_time = current_time;
    end_active_time = current_time;
  } else {
    end_active_time = current_time;
  }
}
void Connection::update_subflows(Packet *p) {
  // uint32_t packet_timestamp = p->pkth->ts.tv_usec;
  int64_t packet_timestamp =
      get_time_in_microseconds(p->pkth->ts.tv_sec, p->pkth->ts.tv_usec);

  if (sf_last_packet_timestamp == -1) {
    sf_last_packet_timestamp = packet_timestamp;
    sf_ac_helper = packet_timestamp;
  }

  if (((packet_timestamp - sf_last_packet_timestamp) / (double)1000000) > 1) {
    sf_count += 1;
    int64_t last_sf_duration = packet_timestamp - sf_ac_helper;
    update_active_idle_time(packet_timestamp - sf_last_packet_timestamp,
                            5000000);
    sf_ac_helper = packet_timestamp;
  }

  sf_last_packet_timestamp = packet_timestamp;
}

std::vector<double> Connection::get_feature_vector() {
  std::vector<double> feature_vector;

  int64_t duration = flow_last_seen - flow_first_seen;

  feature_vector.push_back(server_port); /* 1  */

  feature_vector.push_back(duration); /* 2  */

  feature_vector.push_back(count(forward_pkt));  /* 3  */
  feature_vector.push_back(count(backward_pkt)); /* 4  */
  feature_vector.push_back(sum(forward_pkt));    /* 5  */
  feature_vector.push_back(sum(backward_pkt));   /* 6  */

  /* Forward Packet Length. */
  if (count(forward_pkt) > 0) {
    feature_vector.push_back((max)(forward_pkt));          /* 7  */
    feature_vector.push_back((min)(forward_pkt));          /* 8  */
    feature_vector.push_back(mean(forward_pkt));           /* 9  */
    feature_vector.push_back(sqrt(variance(forward_pkt))); /* 10 */
  } else {
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
  }

  /* Backward Packet Length. */
  if (count(backward_pkt) > 0) {
    feature_vector.push_back((max)(backward_pkt));          /* 11 */
    feature_vector.push_back((min)(backward_pkt));          /* 12 */
    feature_vector.push_back(mean(backward_pkt));           /* 13 */
    feature_vector.push_back(sqrt(variance(backward_pkt))); /* 14 */
  } else {
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
  }

  feature_vector.push_back(get_flowbytespersec()); /* 15 */
  feature_vector.push_back(get_flowpktspersec());  /* 16 */

  /* Flow IAT. */
  if (count(flow_iat) > 0) {
    feature_vector.push_back(mean(flow_iat));           /* 17 */
    feature_vector.push_back(sqrt(variance(flow_iat))); /* 18 */
    feature_vector.push_back((max)(flow_iat));          /* 19 */
    feature_vector.push_back((min)(flow_iat));          /* 20 */
  } else {
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
  }

  /* Forward IAT. */
  if (forward_count > 1) {
    feature_vector.push_back(sum(forward_iat));            /* 21 */
    feature_vector.push_back(mean(forward_iat));           /* 22 */
    feature_vector.push_back(sqrt(variance(forward_iat))); /* 23 */
    feature_vector.push_back((max)(forward_iat));          /* 24 */
    feature_vector.push_back((min)(forward_iat));          /* 25 */
  } else {
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
  }

  /* Backward IAT. */
  if (backward_count > 1) {
    feature_vector.push_back(sum(backward_iat));            /* 26 */
    feature_vector.push_back(mean(backward_iat));           /* 27 */
    feature_vector.push_back(sqrt(variance(backward_iat))); /* 28 */
    feature_vector.push_back((max)(backward_iat));          /* 29 */
    feature_vector.push_back((min)(backward_iat));          /* 30 */
  } else {
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
  }

  feature_vector.push_back(forward_PSH);  /* 31 */
  feature_vector.push_back(backward_PSH); /* 32 */
  feature_vector.push_back(forward_URG);  /* 33 */
  feature_vector.push_back(backward_PSH); /* 34 */

  feature_vector.push_back(forward_hbytes);    /* 35 */
  feature_vector.push_back(backward_hbytes);   /* 36 */
  feature_vector.push_back(get_fpktspersec()); /* 37 */
  feature_vector.push_back(get_bpktspersec()); /* 38 */

  /* Flow Length. */
  if (count(flow_length) > 0) {
    feature_vector.push_back((min)(flow_length));          /* 39 */
    feature_vector.push_back((max)(flow_length));          /* 40 */
    feature_vector.push_back(mean(flow_length));           /* 41 */
    feature_vector.push_back(sqrt(variance(flow_length))); /* 42 */
    feature_vector.push_back(variance(flow_length));       /* 43 */
  } else {
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
  }

  feature_vector.push_back(flags_counter["FIN"]); /* 44 */
  feature_vector.push_back(flags_counter["SYN"]); /* 45 */
  feature_vector.push_back(flags_counter["RST"]); /* 46 */
  feature_vector.push_back(flags_counter["PSH"]); /* 47 */
  feature_vector.push_back(flags_counter["ACK"]); /* 48 */
  feature_vector.push_back(flags_counter["URG"]); /* 49 */
  feature_vector.push_back(flags_counter["CWR"]); /* 50 */
  feature_vector.push_back(flags_counter["ECE"]); /* 51 */

  feature_vector.push_back(get_downupratio());     /* 52 */
  feature_vector.push_back(get_avgpktsize());      /* 53 */
  feature_vector.push_back(get_favgsegmentsize()); /* 54 */
  feature_vector.push_back(get_bavgsegmentsize()); /* 55 */

  feature_vector.push_back(
      forward_hbytes); /* 56
                          This feature is duplicated (35).
                          I'm keeping it because the CICIDS2017's authors kept
                          it in the CSV files used to train the machine
                          learning techniques.
                       */

  feature_vector.push_back(get_favgbytesperbulk()); /* 57 */
  feature_vector.push_back(get_favgpktsperbulk());  /* 58 */
  feature_vector.push_back(get_favgbulkrate());     /* 59 */
  feature_vector.push_back(get_bavgbytesperbulk()); /* 60 */
  feature_vector.push_back(get_bavgpktsperbulk());  /* 61 */
  feature_vector.push_back(get_bavgbulkrate());     /* 62 */

  feature_vector.push_back(get_fsubflowpkts());  /* 63 */
  feature_vector.push_back(get_fsubflowbytes()); /* 64 */
  feature_vector.push_back(get_bsubflowpkts());  /* 65 */
  feature_vector.push_back(get_bsubflowbytes()); /* 66 */

  feature_vector.push_back(init_win_bytes_forward);  /* 67 */
  feature_vector.push_back(init_win_bytes_backward); /* 68 */
  feature_vector.push_back(act_data_pkt_forward);    /* 69 */
  feature_vector.push_back(min_seg_size_forward);    /* 70 */

  /* Flow Active. */
  if (count(flow_active) > 0) {
    feature_vector.push_back(mean(flow_active));           /* 71 */
    feature_vector.push_back(sqrt(variance(flow_active))); /* 72 */
    feature_vector.push_back((max)(flow_active));          /* 73 */
    feature_vector.push_back((min)(flow_active));          /* 74 */
  } else {
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
  }

  /* Flow Idle. */
  if (count(flow_idle) > 0) {
    feature_vector.push_back(mean(flow_idle));           /* 75 */
    feature_vector.push_back(sqrt(variance(flow_idle))); /* 76 */
    feature_vector.push_back((max)(flow_idle));          /* 77 */
    feature_vector.push_back((min)(flow_idle));          /* 78 */
  } else {
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
    feature_vector.push_back(0);
  }

  return feature_vector;
}

void Connection::print_feature_vector(std::vector<double> feature_vector) {
  std::cout << "[";
  for (int i = 0; i < feature_vector.size(); i++) {
    std::cout << "(" << (i + 1) << "): " << feature_vector[i];

    if (i < (feature_vector.size() - 1)) {
      std::cout << " ";
    }
  }
  std::cout << "]" << std::endl;
}
