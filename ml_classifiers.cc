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
#include <ostream>

using namespace snort;

static const char *s_name = "ml_classifiers";
static const char *s_help = "machine learning classifiers";

static THREAD_LOCAL ProfileStats ml_PerfStats;
static THREAD_LOCAL SimpleStats ml_stats;

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
// functional stuff
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
// module stuff
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
// api stuff
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
