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
// Connections.cc + Snippets in ml_classifiers.cc inspired by Luan Utimura's
// ml_classifiers <luan.utimura@gmail.com> which seems to be inspired by the
// CICFLOWMETER Source Code
//--------------------------------------------------------------------------
// The rest : <raoul.ilja.frank@protonmail.com>
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

// Selected parameters configured in snort.lua
std::string classifier_type;
float certaintythresh;
int tt_expired;
int iteration_interval;

// Currently active and expired connections
std::map<std::string, Connection> connections;
TimeoutedConnections expired_connections;

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
  bool is_valid_packet =
      (p->is_tcp() || p->is_udp() || p->is_icmp()) && p->flow;

  if (is_valid_packet) {
    std::string id_candidates = caclulate_flowID(p);

    // Check if matching packet was found and add it or create a new one
    if (connections.find(id_candidates) != connections.end()) {
      connections.find(id_candidates)->second.add_packet(p);
    } else {
      //
      Connection newConnection(p, id_candidates);
      connections.insert(
          std::pair<std::string, Connection>(id_candidates, newConnection));
    }
  }
  ++ml_stats.total_packets;
}

//-------------------------------------------------------------------------
// Packet Inspection Core
//-------------------------------------------------------------------------
void checkConnectionsScheduler() {
  // Repetition can be sepcified via iteration_interval
  // in snort.lua (in seconds). The code saves the iteration_interval (seconds)
  // from the config file as milliseconds
  while (true) {
    int remaining_time = iteration_interval; // Convert milliseconds to seconds
    while (remaining_time > 0) {
      std::cout << "\r\033[K[Info:] Open Connections(" << connections.size()
                << ")" << " - Checking again in: " << remaining_time
                << " seconds" << std::flush; // Flush to ensure immediate output
      std::this_thread::sleep_for(
          std::chrono::seconds(1)); // Sleep for 1 second
      remaining_time--;
    }

    detect_expired_connections(nullptr);
  }
}

void detect_expired_connections(Packet *p) {

  ml_mutex.lock();
  std::map<std::string, Connection> active_connections = connections;
  ml_mutex.unlock();

  for (auto &connection : active_connections) {
    int time_difference;

    time_difference =
        get_time_in_microseconds() - connection.second.get_flowlastseen();

    // If connection has been silent for longer than tt_expired, which is
    // configured in snort.lua, it is added to expired connections struct
    if (time_difference > tt_expired) {
      ml_mutex.lock();

      // Iterator on the openConnections struct pointing to the current
      // (expired) Connection
      std::map<std::string, Connection>::iterator expiredConn_it =
          connections.find(connection.first);

      if (expiredConn_it != connections.end()) {
        // Get the feature vector of the Connection
        std::vector<double> feature_vector =
            expiredConn_it->second.get_feature_vector();

        // ADD connection to expired connections, remove from open connections
        expired_connections.id.push_back(expiredConn_it->second.get_flowid());
        expired_connections.features.push_back(feature_vector);
        expired_connections.connections.push_back(expiredConn_it->second);
        connections.erase(expiredConn_it);
      }
      ml_mutex.unlock();
    }
  }
  // If timeouted connections have been added in this iteration we need to
  // classify them
  if (!expired_connections.id.empty()) {
    classify_expired_connections();
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

      printClassifiedConnections(attack);
    });
  }

  for (auto &thread : classificationThreads) {
    if (thread.joinable()) {
      thread.join();
    }
  }

  delete_expired_connections();
}

std::string caclulate_flowID(Packet *p) {

  std::ostringstream iss;
  p->is_tcp() ? iss << "TCP"
              : (p->is_udp() ? iss << "UDP"
                             : (p->is_icmp() ? iss << "ICMP" : iss << ""));

  // Snippet from forked repo.
  SfIpString client_ip, server_ip;
  p->flow->client_ip.ntop(client_ip);
  p->flow->server_ip.ntop(server_ip);
  iss << "-" << client_ip << ":" << p->flow->client_port << "-" << server_ip
      << ":" << p->flow->server_port;
  if (p->is_icmp()) {
    iss << "-" << p->ptrs.icmph->s_icmp_id;
  }

  return iss.str();
}

void delete_expired_connections() {
  expired_connections.id.clear();
  expired_connections.connections.clear();
  expired_connections.features.clear();
}
//-------------------------------------------------------------------------
// Utility Functions
//-------------------------------------------------------------------------

void createOutputStream() {
  std::string filepath_output = root_dir + "/tmp/timeouted_connections.txt";
  std::ofstream outputFile(filepath_output, std::ios::trunc);
  try {
    if (!outputFile.is_open()) {
      throw std::runtime_error("Unable to open output file: " +
                               filepath_output);
    }

    if (expired_connections.features.empty()) {
      throw std::runtime_error("The features vector is empty.");
    }
    int num_of_features = 77;
    for (int connectionNr = 0; connectionNr < expired_connections.id.size();
         connectionNr++) {
      outputFile << std::fixed << std::setprecision(9);

      for (int featureID = 0; featureID <= num_of_features; featureID++) {
        outputFile << expired_connections.features[connectionNr][featureID];

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
      "python " + root_dir + "/src/utility/csvTransforer.py";

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

      if (predictedValue >= certaintythresh) {
        std::cout << "[!] ML-Classified: " << expired_connections.id[index]
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

//-------------------------------------------------------------------------
// module stuff - Based of example Inspector provided by CISCO/Snort
//-------------------------------------------------------------------------

static const Parameter ml_params[] = {
    {"classifier_type", Parameter::PT_SELECT, " XGB | NN ", "XGB",
     "machine learning classifier"},
    {"mal_threshold_perc", Parameter::PT_INT, "0:100", "90",
     "how certain does the model need to be"},
    {"tt_expired", Parameter::PT_INT, "0:100000", "60",
     "After how many seconds of inactivity is a packet considered expired"},
    {"iteration_interval", Parameter::PT_INT, "0:100000", "20",
     "Every x seconds the plugin should check for new expired conections"},
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
  if (v.is("tt_expired")) {
    tt_expired = v.get_uint16() * 1000000;
    LogMessage("[*] tt_expired: ");
    LogMessage("%s", v.get_string());
    LogMessage("\n");
    std::cout << tt_expired << std::endl;
  }
  if (v.is("iteration_interval")) {
    iteration_interval = v.get_uint16();
    LogMessage("[*] iteration_interval: ");
    LogMessage("%s", v.get_string());
    LogMessage("\n");
    std::cout << iteration_interval << std::endl;
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
