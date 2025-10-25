

/* network_monitor.cpp
 *
 * Single-file Network Packet Analyzer for CS250 Assignment 2
 * Features:
 *  - Custom Queue<T> and Stack<T> (no external DS libraries)
 *  - Packet capture via raw socket (AF_PACKET) in 'live' mode (requires root)
 *  - Simulation mode 'sim' for grading/demo when root is not available
 *  - Dissection of Ethernet, IPv4, IPv6, TCP, UDP using custom parsers
 *  - Filtering by src/dst IP -> filtered list for replay
 *  - Replay with up to 2 retries, backup on persistent failure
 *  - Display functions for packet list and dissected layers
 *
 * Usage:
 *   ./network_monitor sim          # run in simulation/demo mode
 *   sudo ./network_monitor live <interface>  # run live (requires root)
 *
 * Compile:
 *   g++ -std=c++17 -O2 -pthread network_monitor.cpp -o network_monitor
 *
 * Author: Asif Ali
 * Student ID: 520358
 * Course: CS-250 Data Structures and Algorithms
 *
 */

#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <iomanip>
#include <mutex>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <atomic>
#include <random>
#include <sstream>

using namespace std::chrono;
using namespace std;

/* -------------------------
   Custom Data Structures
   ------------------------- */

// Simple singly-linked node
template<typename T>
struct Node {
    T data;
    Node* next;
    Node(const T& d): data(d), next(nullptr) {}
};

// Custom Queue (FIFO)
template<typename T>
class Queue {
private:
    Node<T>* head;
    Node<T>* tail;
    size_t cnt;
public:
    Queue(): head(nullptr), tail(nullptr), cnt(0) {}
    ~Queue() {
        while (head) {
            Node<T>* tmp = head;
            head = head->next;
            delete tmp;
        }
    }
    void enqueue(const T& item) {
        Node<T>* node = new Node<T>(item);
        if (!tail) { head = tail = node; }
        else { tail->next = node; tail = node; }
        cnt++;
    }
    bool dequeue(T& out) {
        if (!head) return false;
        Node<T>* node = head;
        out = head->data;
        head = head->next;
        if (!head) tail = nullptr;
        delete node;
        cnt--;
        return true;
    }
    bool isEmpty() const { return head == nullptr; }
    size_t size() const { return cnt; }
    // peek first element (not remove)
    bool peek(T& out) const {
        if (!head) return false;
        out = head->data;
        return true;
    }
};

// Custom Stack (LIFO)
template<typename T>
class Stack {
private:
    Node<T>* topNode;
    size_t cnt;
public:
    Stack(): topNode(nullptr), cnt(0) {}
    ~Stack() {
        while (topNode) {
            Node<T>* tmp = topNode;
            topNode = topNode->next;
            delete tmp;
        }
    }
    void push(const T& item) {
        Node<T>* node = new Node<T>(item);
        node->next = topNode;
        topNode = node;
        cnt++;
    }
    bool pop(T& out) {
        if (!topNode) return false;
        Node<T>* node = topNode;
        out = node->data;
        topNode = topNode->next;
        delete node;
        cnt--;
        return true;
    }
    bool top(T& out) const {
        if (!topNode) return false;
        out = topNode->data;
        return true;
    }
    bool isEmpty() const { return topNode == nullptr; }
    size_t size() const { return cnt; }
};

/* -------------------------
   Packet and Layer Types
   ------------------------- */

struct Packet {
    uint64_t id;
    time_t ts;
    vector<uint8_t> buf;       // raw packet buffer
    string src_ip;
    string dst_ip;
    size_t retries = 0;
    bool dissected = false;
    // store string representation of parsed layers for display
    vector<string> layers;
};

enum LayerType {
    L_ETHERNET,
    L_IPV4,
    L_IPV6,
    L_TCP,
    L_UDP,
    L_UNKNOWN
};

struct Layer {
    LayerType type;
    string info;
    Layer(LayerType t=L_UNKNOWN, string i=""): type(t), info(i) {}
};

/* -------------------------
   Dissector (custom parsers)
   ------------------------- */

class Dissector {
public:
    static void dissect(Packet& p) {
        p.layers.clear();
        // Use a stack of layers (we'll push raw buffer, then pop parse results)
        Stack<Layer> layerStack;
        // Start with Ethernet
        if (p.buf.size() < sizeof(ethhdr)) {
            layerStack.push(Layer(L_UNKNOWN, "truncated"));
            flushStackToPacket(p, layerStack);
            p.dissected = true;
            return;
        }
        const ethhdr* eth = reinterpret_cast<const ethhdr*>(p.buf.data());
        uint16_t eth_type = ntohs(eth->h_proto);
        {
            std::ostringstream oss;
            oss << "Ethernet: proto=0x" << std::hex << eth_type << std::dec;
            layerStack.push(Layer(L_ETHERNET, oss.str()));
        }
        // IPv4
        if (eth_type == ETH_P_IP) {
            if (p.buf.size() < sizeof(ethhdr) + sizeof(iphdr)) {
                layerStack.push(Layer(L_UNKNOWN, "truncated ipv4"));
                flushStackToPacket(p, layerStack);
                p.dissected = true;
                return;
            }
            const iphdr* iph = reinterpret_cast<const iphdr*>(p.buf.data() + sizeof(ethhdr));
            char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &iph->saddr, saddr, sizeof(saddr));
            inet_ntop(AF_INET, &iph->daddr, daddr, sizeof(daddr));
            p.src_ip = string(saddr);
            p.dst_ip = string(daddr);

            {
                std::ostringstream oss;
                oss << "IPv4: proto=" << int(iph->protocol) << " ttl=" << int(iph->ttl);
                layerStack.push(Layer(L_IPV4, oss.str()));
            }

            // offset to transport
            size_t ihl = iph->ihl * 4;
            size_t ip_offset = sizeof(ethhdr) + ihl;
            if (iph->protocol == IPPROTO_TCP) {
                if (p.buf.size() >= ip_offset + sizeof(tcphdr)) {
                    const tcphdr* th = reinterpret_cast<const tcphdr*>(p.buf.data() + ip_offset);
                    {
                        std::ostringstream oss;
                        oss << "TCP: sport=" << ntohs(th->source) << " dport=" << ntohs(th->dest);
                        layerStack.push(Layer(L_TCP, oss.str()));
                    }
                } else {
                    layerStack.push(Layer(L_UNKNOWN, "truncated tcp"));
                }
            } else if (iph->protocol == IPPROTO_UDP) {
                if (p.buf.size() >= ip_offset + sizeof(udphdr)) {
                    const udphdr* uh = reinterpret_cast<const udphdr*>(p.buf.data() + ip_offset);
                    {
                        std::ostringstream oss;
                        oss << "UDP: sport=" << ntohs(uh->source) << " dport=" << ntohs(uh->dest);
                        layerStack.push(Layer(L_UDP, oss.str()));
                    }
                } else {
                    layerStack.push(Layer(L_UNKNOWN, "truncated udp"));
                }
            } else {
                layerStack.push(Layer(L_UNKNOWN, "unknown transport"));
            }
        }
        // IPv6
        else if (eth_type == ETH_P_IPV6) {
            if (p.buf.size() < sizeof(ethhdr) + sizeof(ip6_hdr)) {
                layerStack.push(Layer(L_UNKNOWN, "truncated ipv6"));
                flushStackToPacket(p, layerStack);
                p.dissected = true;
                return;
            }
            const ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(p.buf.data() + sizeof(ethhdr));
            char saddr6[INET6_ADDRSTRLEN], daddr6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip6->ip6_src, saddr6, sizeof(saddr6));
            inet_ntop(AF_INET6, &ip6->ip6_dst, daddr6, sizeof(daddr6));
            p.src_ip = string(saddr6);
            p.dst_ip = string(daddr6);

            {
                std::ostringstream oss;
                oss << "IPv6: payload_len=" << ntohs(ip6->ip6_plen);
                layerStack.push(Layer(L_IPV6, oss.str()));
            }
            // For simplicity, we won't parse extension headers deeply here.
            // Check next header for TCP/UDP
            int nh = ip6->ip6_nxt;
            size_t ip6_offset = sizeof(ethhdr) + sizeof(ip6_hdr);
            if (nh == IPPROTO_TCP) {
                if (p.buf.size() >= ip6_offset + sizeof(tcphdr)) {
                    const tcphdr* th = reinterpret_cast<const tcphdr*>(p.buf.data() + ip6_offset);
                    std::ostringstream oss;
                    oss << "TCP: sport=" << ntohs(th->source) << " dport=" << ntohs(th->dest);
                    layerStack.push(Layer(L_TCP, oss.str()));
                } else layerStack.push(Layer(L_UNKNOWN, "truncated tcp"));
            } else if (nh == IPPROTO_UDP) {
                if (p.buf.size() >= ip6_offset + sizeof(udphdr)) {
                    const udphdr* uh = reinterpret_cast<const udphdr*>(p.buf.data() + ip6_offset);
                    std::ostringstream oss;
                    oss << "UDP: sport=" << ntohs(uh->source) << " dport=" << ntohs(uh->dest);
                    layerStack.push(Layer(L_UDP, oss.str()));
                } else layerStack.push(Layer(L_UNKNOWN, "truncated udp"));
            } else {
                layerStack.push(Layer(L_UNKNOWN, "unknown transport"));
            }
        } else {
            // unknown ethertype
            std::ostringstream oss;
            oss << "Unknown ethertype: 0x" << std::hex << eth_type << std::dec;
            layerStack.push(Layer(L_UNKNOWN, oss.str()));
        }

        flushStackToPacket(p, layerStack);
        p.dissected = true;
    }

private:
    static void flushStackToPacket(Packet& p, Stack<Layer>& st) {
        // Pop all items and append to packet.layers in top-down order
        vector<string> tmp;
        Layer L;
        while (st.pop(L)) {
            tmp.push_back(L.info);
        }
        // tmp currently has bottom-first because we pushed ethernet then others? We popped top-first,
        // but to show layers in order from outer to inner, reverse tmp.
        for (auto it = tmp.rbegin(); it != tmp.rend(); ++it) {
            p.layers.push_back(*it);
        }
    }
}; // Dissector

/* -------------------------
   Packet Manager & Globals
   ------------------------- */

atomic<uint64_t> global_packet_id{1};

// Shared queues
Queue<Packet>* capturedQueue = nullptr;  // main captured packets
Queue<Packet>* filteredQueue = nullptr;  // packets ready for replay
Queue<Packet>* backupQueue = nullptr;    // backup for failed replays

mutex capMutex, filterMutex, backupMutex; // protect each queue

// Settings
size_t OVERSIZE_LIMIT = 1500;
size_t OVERSIZE_SKIP_THRESHOLD = 5; // if oversize count exceeds this, skip further oversized
atomic<int> oversizeCount{0};

// Filtering config (set in main)
string filter_src = "";
string filter_dst = "";

// Control flags
atomic<bool> running{true};

/* --------------
   Helpers
   -------------- */

string ts_to_string(time_t t) {
    std::tm tm = *std::localtime(&t);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%F %T", &tm);
    return string(buf);
}

void print_packet_summary(const Packet& p) {
    cout << "ID=" << p.id << " ts=" << ts_to_string(p.ts)
         << " size=" << p.buf.size()
         << " src=" << p.src_ip << " dst=" << p.dst_ip << "\n";
}

void print_packet_layers(const Packet& p) {
    cout << "Dissected layers for packet " << p.id << ":\n";
    for (size_t i=0;i<p.layers.size();++i) {
        cout << "  [" << i << "] " << p.layers[i] << "\n";
    }
}

/* -------------------------
   Capture (live) and Simulate
   ------------------------- */

// Live capture using AF_PACKET raw socket
int open_raw_socket(const string& iface) {
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sd == -1) {
        perror("socket");
        return -1;
    }
    // bind to interface
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        close(sd);
        return -1;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;
    if (bind(sd, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
        perror("bind");
        close(sd);
        return -1;
    }
    return sd;
}

void capture_thread_live(const string& iface) {
    int sd = open_raw_socket(iface);
    if (sd < 0) {
        cerr << "Failed to open raw socket on " << iface << ". Exiting capture thread.\n";
        return;
    }
    cout << "[CAPTURE] live capture started on " << iface << "\n";
    while (running) {
        uint8_t buffer[65536];
        ssize_t len = recv(sd, buffer, sizeof(buffer), 0);
        if (len <= 0) continue;
        Packet p;
        p.id = global_packet_id++;
        p.ts = time(nullptr);
        p.buf.assign(buffer, buffer + len);
        // oversize handling
        if (p.buf.size() > OVERSIZE_LIMIT) {
            int cur = ++oversizeCount;
            if (cur > (int)OVERSIZE_SKIP_THRESHOLD) {
                cout << "[CAPTURE] skipping oversized packet id=" << p.id << " size=" << p.buf.size() << "\n";
                continue;
            }
        }
        // enqueue
        {
            lock_guard<mutex> g(capMutex);
            capturedQueue->enqueue(p);
        }
    }
    close(sd);
}

// Simulation of packet capture (for grading / demo without root)
void capture_thread_simulated() {
    cout << "[CAPTURE] simulation mode started\n";
    std::mt19937_64 rng((uint64_t)time(nullptr));
    std::uniform_int_distribution<int> sizeDist(60, 1600); // generate possibly oversized
    std::uniform_int_distribution<int> ipPart(1, 254);
    std::uniform_int_distribution<int> proto(0, 1); // 0 tcp, 1 udp

    auto rand_ip = [&](){
        std::ostringstream o;
        o << ipPart(rng) << "." << ipPart(rng) << "." << ipPart(rng) << "." << ipPart(rng);
        return o.str();
    };

    while (running) {
        Packet p;
        p.id = global_packet_id++;
        p.ts = time(nullptr);
        int len = sizeDist(rng);
        p.buf.resize(len);
        // Fill with pseudo-ethernet + ip header so dissector can parse some fields (simplified)
        // We'll set ethertype to IPv4, then a minimal IPv4 header with random src/dst
        if (len >= (int)(sizeof(ethhdr) + sizeof(iphdr) + 20)) {
            ethhdr* eh = reinterpret_cast<ethhdr*>(p.buf.data());
            memset(eh, 0, sizeof(ethhdr));
            eh->h_proto = htons(ETH_P_IP);
            // ip header after eth
            iphdr* iph = reinterpret_cast<iphdr*>(p.buf.data() + sizeof(ethhdr));
            memset(iph, 0, sizeof(iphdr));
            iph->ihl = 5;
            iph->version = 4;
            iph->protocol = (proto(rng)==0? IPPROTO_TCP : IPPROTO_UDP);
            iph->saddr = inet_addr(rand_ip().c_str());
            iph->daddr = inet_addr(rand_ip().c_str());
            // set TCP/UDP headers if space
            size_t ip_offset = sizeof(ethhdr) + iph->ihl*4;
            if (iph->protocol == IPPROTO_TCP && p.buf.size() >= ip_offset + sizeof(tcphdr)) {
                tcphdr* th = reinterpret_cast<tcphdr*>(p.buf.data() + ip_offset);
                memset(th, 0, sizeof(tcphdr));
                th->source = htons(1000 + (rng()%40000));
                th->dest = htons(2000 + (rng()%40000));
            } else if (iph->protocol == IPPROTO_UDP && p.buf.size() >= ip_offset + sizeof(udphdr)) {
                udphdr* uh = reinterpret_cast<udphdr*>(p.buf.data() + ip_offset);
                memset(uh, 0, sizeof(udphdr));
                uh->source = htons(1000 + (rng()%40000));
                uh->dest = htons(2000 + (rng()%40000));
            }
        }
        if (p.buf.size() > OVERSIZE_LIMIT) {
            int cur = ++oversizeCount;
            if (cur > (int)OVERSIZE_SKIP_THRESHOLD) {
                cout << "[CAPTURE] (sim) skipping oversized packet id=" << p.id << " size=" << p.buf.size() << "\n";
                std::this_thread::sleep_for(milliseconds(50));
                continue;
            }
        }
        {
            lock_guard<mutex> g(capMutex);
            capturedQueue->enqueue(p);
        }
        std::this_thread::sleep_for(milliseconds(100)); // simulate packet arrival rate
    }
}

/* -------------------------
   Dissector thread
   ------------------------- */

void dissector_thread_func() {
    cout << "[DISSECTOR] started\n";
    while (running) {
        Packet p;
        bool got = false;
        {
            lock_guard<mutex> g(capMutex);
            if (!capturedQueue->isEmpty()) {
                capturedQueue->dequeue(p);
                got = true;
            }
        }
        if (!got) {
            std::this_thread::sleep_for(milliseconds(50));
            continue;
        }
        // Dissect
        Dissector::dissect(p);
        // Check filter
        bool match = true;
        if (!filter_src.empty()) {
            if (p.src_ip != filter_src) match = false;
        }
        if (!filter_dst.empty()) {
            if (p.dst_ip != filter_dst) match = false;
        }
        if (match) {
            lock_guard<mutex> g(filterMutex);
            filteredQueue->enqueue(p);
            cout << "[FILTER] packet " << p.id << " matched filter. queued for replay\n";
        } else {
            // Not matched; we could discard or log
        }
    }
}

/* -------------------------
   Replay thread
   ------------------------- */

// Simulated send: randomly fail to demonstrate retry/backups
bool simulated_send(const Packet& p) {
    // fail 20% of the time
    static thread_local std::mt19937 rng((uint64_t)time(nullptr) ^ std::hash<std::thread::id>()(std::this_thread::get_id()));
    std::uniform_int_distribution<int> d(1, 10);
    int r = d(rng);
    this_thread::sleep_for(milliseconds((int)max(1u, (unsigned)(p.buf.size()/1000))));
    return r > 2; // 80% success
}

// live send using raw AF_PACKET socket (requires root & same interface binding)
bool live_send_on_iface(const Packet& p, const string& iface) {
    // Open a raw socket and send the buffer (needs root)
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sd < 0) {
        perror("socket send");
        return false;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl ifindex");
        close(sd);
        return false;
    }
    struct sockaddr_ll saddr = {0};
    saddr.sll_ifindex = ifr.ifr_ifindex;
    saddr.sll_halen = ETH_ALEN;
    saddr.sll_family = AF_PACKET;
    // Destination MAC zero -> kernel may decide. For demonstration, attempt send.
    ssize_t sent = sendto(sd, p.buf.data(), p.buf.size(), 0, (struct sockaddr*)&saddr, sizeof(saddr));
    close(sd);
    return (sent == (ssize_t)p.buf.size());
}

void replay_thread_func(const string& mode, const string& iface) {
    cout << "[REPLAY] started in mode=" << mode << "\n";
    while (running) {
        Packet p;
        bool got = false;
        {
            lock_guard<mutex> g(filterMutex);
            if (!filteredQueue->isEmpty()) {
                filteredQueue->dequeue(p);
                got = true;
            }
        }
        if (!got) {
            std::this_thread::sleep_for(milliseconds(50));
            continue;
        }
        // estimate delay
        double delay_ms = double(p.buf.size()) / 1000.0;
        cout << "[REPLAY] attempting packet id=" << p.id << " estimated delay=" << fixed << setprecision(2) << delay_ms << "ms\n";
        bool ok = false;
        if (mode == "sim") {
            ok = simulated_send(p);
        } else {
            ok = live_send_on_iface(p, iface);
        }
        if (!ok) {
            p.retries++;
            cout << "[REPLAY] send failed for id=" << p.id << " retry=" << p.retries << "\n";
            if (p.retries <= 2) {
                // re-enqueue to filteredQueue for retry
                lock_guard<mutex> g(filterMutex);
                filteredQueue->enqueue(p);
                cout << "[REPLAY] requeued id=" << p.id << " for retry\n";
            } else {
                // move to backup
                lock_guard<mutex> g(backupMutex);
                backupQueue->enqueue(p);
                cout << "[REPLAY] moved id=" << p.id << " to backup after 2 retries\n";
            }
        } else {
            cout << "[REPLAY] send succeeded for id=" << p.id << "\n";
            // done
        }
        // small sleep to avoid busy loop
        std::this_thread::sleep_for(milliseconds(10));
    }
}

/* -------------------------
   Display / Demo helpers
   ------------------------- */

void display_thread_func() {
    while (running) {
        this_thread::sleep_for(seconds(5));
        cout << "=== Current Packet Summary ===\n";
        // Note: we will not dequeue; just show front items if any.
        lock_guard<mutex> g(capMutex);
        // For demo we just show count
        cout << "Captured queue size: " << capturedQueue->size() << "\n";
        cout << "Filtered queue size: " << filteredQueue->size() << "\n";
        cout << "Backup queue size: " << backupQueue->size() << "\n";
        cout << "Oversize count: " << oversizeCount.load() << "\n";
    }
}

/* -------------------------
   Main & Demo
   ------------------------- */

int main(int argc, char* argv[]) {
    cout << "Network Monitor (CS250 Assignment 2) Demo\n";
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " sim    OR   sudo " << argv[0] << " live <interface>\n";
        return 1;
    }
    string mode = argv[1];
    string iface = (argc >= 3 ? argv[2] : "");

    if (mode != "sim" && mode != "live") {
        cout << "Invalid mode. Use 'sim' or 'live'\n";
        return 1;
    }
    if (mode == "live" && iface.empty()) {
        cout << "Live mode requires interface name, e.g., eth0\n";
        return 1;
    }

    // init queues
    capturedQueue = new Queue<Packet>();
    filteredQueue = new Queue<Packet>();
    backupQueue = new Queue<Packet>();

    // configure filter (for demo, we can set sample IPs or accept from user)
    cout << "Enter source IP filter (empty for any): ";
    string s;
    getline(cin, s);
    filter_src = s;
    cout << "Enter destination IP filter (empty for any): ";
    getline(cin, s);
    filter_dst = s;

    // Start threads
    thread capThread;
    if (mode == "sim") capThread = thread(capture_thread_simulated);
    else capThread = thread(capture_thread_live, iface);

    thread disThread(dissector_thread_func);
    thread repThread(replay_thread_func, mode, iface);
    thread dispThread(display_thread_func);

    // Run for 60 seconds demo (assignment requires at least 1 minute)
    cout << "Demo running for 60 seconds...\n";
    auto start = steady_clock::now();
    while (duration_cast<seconds>(steady_clock::now() - start).count() < 60) {
        std::this_thread::sleep_for(milliseconds(200));
    }

    // Stop
    running = false;
    cout << "Shutting down threads...\n";
    if (capThread.joinable()) capThread.join();
    if (disThread.joinable()) disThread.join();
    if (repThread.joinable()) repThread.join();
    if (dispThread.joinable()) dispThread.join();

    // Final display
    cout << "Final summary:\n";
    cout << "Captured queue size: " << capturedQueue->size() << "\n";
    cout << "Filtered queue size: " << filteredQueue->size() << "\n";
    cout << "Backup queue size: " << backupQueue->size() << "\n";

    // Show some backup packets (if any)
    cout << "Backup packets:\n";
    Packet p;
    while (backupQueue->dequeue(p)) {
        print_packet_summary(p);
        if (p.dissected) print_packet_layers(p);
    }

    // Clean up
    delete capturedQueue;
    delete filteredQueue;
    delete backupQueue;
    cout << "Demo complete. Exiting.\n";
    return 0;
}
