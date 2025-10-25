# 🧩 CS250 – Network Packet Analyzer (Assignment 2)

**Course:** CS-250: Data Structures and Algorithms  
**Class:** BSDS 2A  
**Instructor:** Dr. Fahad Ahmed Satti  
**Student:** Asif Ali (520358)  
**University:** National University of Science and Technology (NUST), SEECS  

---

## 📘 Project Overview
This project implements a **Network Packet Analyzer** using **C++** to demonstrate the application of **data structures** such as **stacks** and **queues** in real-world networking scenarios.  
The analyzer simulates **packet capture, dissection, filtering, and replay**, fulfilling the functional and rubric requirements of Assignment 2.

---

## 🎯 Objectives
- Implement core data structures (Queue, Stack) using linked lists.  
- Apply OOP principles and algorithms to manage packet flow.  
- Simulate real-time packet capture and dissection without root privileges.  
- Demonstrate multi-threading, filtering, and replay logic.  

---

## 🏗️ System Architecture
The system is modular and follows a multi-threaded design:

1. **Capture Module** – Simulates real-time packet capture and enqueues packets.  
2. **Dissector Module** – Dequeues and dissects packets into protocol layers.  
3. **Filter Module** – Filters packets by source and destination IP.  
4. **Replay Module** – Replays packets with retry and backup mechanisms.  
5. **Backup Module** – Stores failed packets for future analysis.  

---

## ⚙️ Data Structures Used
| Data Structure | Purpose | Implementation |
|----------------|----------|----------------|
| **Queue** | Stores captured packets (FIFO) | Linked List Template |
| **Stack** | Manages protocol dissection layers (LIFO) | Linked List Template |

---

## 🧠 Key Concepts Demonstrated
- Object-Oriented Programming (Encapsulation, Inheritance, Abstraction)  
- Custom Data Structure Implementation  
- Thread Synchronization  
- Exception Handling  
- Packet Simulation and Processing  

---
## 💻 How to Run
1. Clone this repository  
   ```bash
   git clone https://github.com/asifaliansaree/CS250-NetworkAnalyzer.git
   cd CS250-NetworkAnalyzer
   ```
2. Compile and run  
   ```bash
   g++ network_monitor.cpp -o analyzer -pthread
   ./analyzer
   ```

## 📂 File Structure
```
📁 CS250-NetworkAnalyzer
├── network_monitor.cpp
├── README.md
├── Assignment_2_Report_with_Code_and_Screenshots.docx
├── screenshots/
│   ├── capture_output.png
│   ├── dissection_log.png
│   ├── replay_results.png
│   ├── backup_summary.png
└── LICENSE
```

### 🏁 Acknowledgment
This project was completed as part of **CS250: Data Structures and Algorithms** under the supervision of **Dr. Fahad Ahmed Satti**, NUST SEECS.
