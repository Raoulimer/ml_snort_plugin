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
// Connections.cc inspired by Luan Utimura's ml_classifiers
// <luan.utimura@gmail.com> which seems to be inspired by the CICFLOWMETER
// Source Code
//--------------------------------------------------------------------------
// Everything else from Raoul Frank <raoul.ilja.frank@protonmail.com>
//--------------------------------------------------------------------------

// My headers
#include "include/ml_classifiers.h"
#include "framework/parameter.h"
#include "src/featureExtraction/connection.h"

// Stuff from Cisco that every inspector uses
#include "detection/detection_engine.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "profiler/profiler.h"

// Protocols
#include "protocols/icmp4.h"
#include "protocols/packet.h"

// Utility
#include <boost/python.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>

// Multithreading
#include <mutex>
#include <ostream>
#include <thread>

//-------------------------------------------------------------------------
// GLOBAL
//-------------------------------------------------------------------------
using namespace snort;

std::string root_dir = std::string(PROJECT_ROOT_DIR);

static const char *s_name = "ml_classifiers";
static const char *s_help = "machine learning classifiers";

std::mutex ml_mutex;
static THREAD_LOCAL ProfileStats ml_PerfStats;
static THREAD_LOCAL SimpleStats ml_stats;

// Selected classifier type
std::string classifier_type;
float certaintythresh;
// Currently active (not expired) connections
std::map<std::string, Connection> connections;
std::map<std::string, Connection>::iterator connections_it;

TimeoutedConnections t_connections;

//-------------------------------------------------------------------------
// Inspector Inheritance
//-------------------------------------------------------------------------

class MLClassifiers : public Inspector {
private:
public:
  MLClassifiers();

  bool configure(SnortConfig *) override;
  void show(const SnortConfig *) const override;
  void eval(Packet *) override;
};

MLClassifiers::MLClassifiers() {
  LogMessage("[Info:] MLClassifiers::MLClassifiers()\n");
}

bool MLClassifiers::configure(SnortConfig *) {
  std::thread verify_thread(checkConnectionsScheduler);
  verify_thread.detach();
  return true;
}

void MLClassifiers::show(const SnortConfig *) const {
  LogMessage("[Info:] MLClassifers::show\n");
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
  std::string filepath_output = root_dir + "/tmp/timeouted_connections.txt";
  std::ofstream outputFile(filepath_output, std::ios::trunc);
  try {
    if (!outputFile.is_open()) {
      throw std::runtime_error("Unable to open output file: " +
                               filepath_output);
    }

    if (t_connections.features.empty()) {
      throw std::runtime_error("The features vector is empty.");
    }
    int num_of_features = 77;
    for (int connectionNr = 0; connectionNr < t_connections.id.size();
         connectionNr++) {
      outputFile << std::fixed << std::setprecision(9);

      for (int featureID = 0; featureID <= num_of_features; featureID++) {
        outputFile << t_connections.features[connectionNr][featureID];

        if (featureID == num_of_features)
          outputFile << std::scientific << "\n";
        else
          outputFile << " ";
      }
    }
    outputFile.close();
  } catch (const std::runtime_error &e) {
    std::cerr << "Runtime error: " << e.what() << std::endl;
  }
}

void transformOutputStream() {
  std::string transform_cmd =
      "python " + root_dir + "/src/python-utility/csvTransforer.py";

  int exit_status = system(transform_cmd.c_str());
  if (exit_status != 0) {
    std::cerr << "Error: Command failed with error code " << exit_status
              << std::endl;
  }
}

void printClassifiedConnections(std::string attackName) {
  try {
    std::string filepath_input =
        root_dir + "/tmp/timeouted_connections_results" + attackName + ".txt";
    std::ifstream inputFile(filepath_input);

    if (!inputFile.is_open()) {
      throw std::runtime_error("Unable to open input file: " + filepath_input);
    }
    std::string line;
    uint32_t index = 0;

    while (std::getline(inputFile, line)) {
      float predictedValue;
      std::istringstream iss(line);
      iss >> predictedValue;

      std::cout << "Debug" << certaintythresh;
      if (predictedValue >= certaintythresh) {
        std::cout << "[!] ML-Classified: " << t_connections.id[index]
                  << "\tResult: " << "Attack (" << predictedValue << ") - "
                  << attackName << std::endl;
      }

      index++;
    }

    inputFile.close();

  } catch (const std::runtime_error &e) {
    std::cerr << "Runtime error: " << e.what() << std::endl;
  }
}

void classify_expired_connections() {
  createOutputStream();
  transformOutputStream();

  std::vector<std::thread> classificationThreads;
  std::string attackTypes[] = {"ddos", "bruteforce", "botnet", "sql",
                               "infiltration"};

  for (const std::string &attack : attackTypes) {
    classificationThreads.emplace_back([attack]() {
      std::cout << "Debug: Calling " + attack + " Classifier" << std::endl;

      std::string predict_cmd =
          "python " + root_dir +
          "/src/machineLearning/ml_models/IntrusionModelNetworkPredictor.py " +
          attack;
      system(predict_cmd.c_str());

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
// Packet Inspection Core
//-------------------------------------------------------------------------
void checkConnectionsScheduler() {
  // Thread's run function. Runs every 20 sec.
  while (true) {
    std::cout << "[Info:] Open Connections(" << connections.size() << ")"
              << std::endl;

    detect_expired_connections(nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(20000));
  }
}

void detect_expired_connections(Packet *p) {
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

    // Connection is considered expired after 1 min of silence
    if (time_difference > 60000000) {
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
    classify_expired_connections();
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
    {"classifier_type", Parameter::PT_SELECT, "ddos | XGB | NN ", "XGB",
     "machine learning classifier"},
    {"mal_threshold_perc", Parameter::PT_INT, "0:100", "90",
     "how certain does the model need to be"},
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
  LogMessage("[Info:] MLClassifiersModule::set\n");
  if (v.is("classifier_type")) {
    classifier_type = v.get_string();
    LogMessage("[*] classifier_type: ");
    LogMessage("%s", v.get_string());
    LogMessage("\n");
    std::cout << classifier_type << std::endl;
  }
  if (v.is("mal_threshold_perc")) {
    certaintythresh = v.get_uint16() / 100.0;
    LogMessage("[*] mal_threshold_perc: ");
    LogMessage("%s", v.get_string());
    LogMessage("\n");
    std::cout << certaintythresh << std::endl;
  }

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
