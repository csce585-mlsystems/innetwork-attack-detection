# Project Title  
## Intelligent In-Network Attack Detection 

## Group Info  
- Sergio Elizalde  
  - Email: elizalds@email.sc.edu
- Samia Choueiri  
  - Email: choueiri@email.sc.edu 
- Amith GSPN  
  - Email: amithgspn@sc.edu 

## Project Summary/Abstract  
### This project focuses on deploying an intelligent in-network attack detection system powered by machine learning to enhance real-time cybersecurity defenses. The system will be evaluated for performance in terms of latency and throughput to ensure minimal impact on network efficiency. Deployment and validation will be conducted on a real-world testbed, such as the USC datacenter or the FABRIC national testbed, to demonstrate scalability and practical effectiveness. 

## Problem Description  
- Problem description: As network speeds continue to increase and cyberattacks grow in sophistication, traditional defense mechanisms struggle to keep pace. Conventional approaches often cannot efficiently inspect the massive volumes of traffic, much of which is encrypted, without introducing significant performance bottlenecks. To address these limitations, distributed architectures and hardware-accelerated solutions are emerging as promising alternatives for scalable and effective network defense.
  
- Motivation  
  - The rapid growth of network traffic and encrypted communication requires scalable, intelligent security mechanisms that can operate in real time.  
  - Traditional centralized intrusion detection systems cannot handle the volume and speed of modern data flows without causing performance degradation.  
  - Deploying machine learning–based, in-network detection systems on real testbeds (e.g., USC datacenter, FABRIC) provides a practical path to evaluate and advance next-generation cybersecurity solutions.  
- Challenges  
  - Designing ML models that can accurately detect evolving attack patterns while maintaining low false positives in high-speed environments.  
  - Ensuring system performance by minimizing added latency and maintaining high throughput during live deployment.  
  - Integrating the system into real-world testbeds with heterogeneous infrastructure and validating scalability under realistic traffic conditions. 
 
## Contribution  
### [`Novel contribution`]    
- Deploy machine learning models within programmable in-network devices by overcoming hardware constraints and optimizing model placement.
- Map machine learning algorithms to network device architectures and validate their performance on real-world testbeds such as the USC datacenter and FABRIC. 

## References  
[1] K. Tasdemir, R. Khan, F. Siddiqui, S. Sezer, F. Kurugollu and A. Bolat, "An Investigation of Machine Learning Algorithms for High-bandwidth SQL Injection Detection Utilising BlueField-3 DPU Technology," 2023 IEEE 36th International System-on-Chip Conference (SOCC), Santa Clara, CA, USA.

[2] Kapoor, R., Anastasiu, D. C., & Choi, S. (2025). ML-NIC: accelerating machine learning inference using smart network interface cards. Frontiers in Computer Science, 6, 1493399.

[3] M. Wu, H. Matsutani and M. Kondo, "ONLAD-IDS: ONLAD-Based Intrusion Detection System Using SmartNIC," 2022 IEEE 24th Int Conf on High Performance Computing & Communications; 8th Int Conf on Data Science & Systems; 20th Int Conf on Smart City; 8th Int Conf on Dependability in Sensor, Cloud & Big Data Systems & Application (HPCC/DSS/SmartCity/DependSys), Hainan, China.

[4] B. M. Xavier, R. S. Guimarães, G. Comarela and M. Martinello, "Programmable Switches for in-Networking Classification," IEEE INFOCOM 2021 - IEEE Conference on Computer Communications, Vancouver, BC, Canada.

[Link to BibTeX file](references.bib)

# Reproducing Code for Milestone P1
1. Change to code directory ```cd code```
2. Run the Jupyter notebook ```data_preprocess.ipynb```

## Dependencies  
- Python 3.12.12  
- Numpy
- Pandas
- Matplotlib
- Seaborn
- tqdm 
- IPython
- gc
- sklearn
- tensorflow
- xgboost
- lightgbm
- catboost
- re
- warnings
- csv
- json
- argparse
- graphviz
- pickle
- collections
- os
- sys
- statistics
- random
- scapy
- netaddr
---
- DPDK
- p4c
- Mellanox Drivers

## Directory Structure   
```
|- .gitignore
|- README.md
|- references.bib
|- code
|   |- CSCE580 - Offline Analysis Report.ipynb
|   |- pcap-preprocessing.ipynb
|   |- P4DPDK-DDoS
|   |   |- Online-Deployment.ipynb
|   |   |- figs
|   |   |- out-benign.pcap
|   |   |- out-ddos.pcap
|   |   |- scripts
|   |   |   |- code
|   |   |   |   |- classifier.p4
|   |   |   |   |- features_extract.p4
|   |   |   |   |- pipeline.cli
|   |   |   |   |- pipeline1.io
|   |   |   |   |- pipeline2.io
|   |   |   |- data
|   |   |   |   |- BenignTraffic_test.pcap
|   |   |   |   |- DDoS-HTTP_Flood-_test.pcap
|   |   |   |   |- out-benign.pcap.pcap
|   |   |   |- host_tune.sh
|   |   |   |- install.sh
|   |   |   |- nat64.sh
|   |   |   |- pcap_classification_extraction.sh
|   |   |   |- rte_swx_pipeline.c
|   |   |   |- rte_swx_pipeline_internal.h
|   |   |   |- rules
|   |   |   |   |- rules_code_table0.txt
|   |   |   |   |- rules_code_table1.txt
|   |   |   |   |- rules_code_table2.txt
|   |   |   |   |- rules_iat_max.txt
|   |   |   |   |- rules_iat_min.txt
|   |   |   |   |- rules_max_differential_packet_length.txt
|   |   |   |   |- rules_min_differential_packet_length.txt
|   |   |   |   |- rules_packet_length_total.txt
|   |   |   |   |- rules_voting_table.txt
|   |   |   |- run_pipeline.sh
|   |   |   |- setup.sh
|- data
|   |- links-to-data.md
|   |- test_data_CIC.csv
|   |- train_data_CIC.csv
|- doc
|   |- Demo Milestone P2 — Final Report and Presentation.mp4
|   |- Milestone P0 — Project Proposal and Motivation.pdf
|   |- Milestone P1 — Initial Experiment and Evaluation Setup.pdf
|   |- Milestone P2 — Final Report and Presentation.pdf
|   |- Slides Milestone P0 — Project Proposal and Motivation.pdf
|   |- Slides Milestone P1 — Initial Experiment and Evaluation Setup.pdf
|   |- Slides Milestone P2 — Final Report and Presentation.pdf
|   |- Slides Milestone P2 — Final Report and Presentation.pptx
|- results
|   |- rf_model_cic.pkl
|   |- rules_code_table0.txt
|   |- rules_code_table1.txt
|   |- rules_code_table2.txt
|   |- rules_iat_max.txt
|   |- rules_iat_min.txt
|   |- rules_max_differential_packet_length.txt
|   |- rules_min_differential_packet_length.txt
|   |- rules_packet_length_total.txt
|   |- rules_voting_table.txt
```

⚠️ Notes:  
- To run the project please follow the instruction in the "How to Run" section  
- All computed metrics are included and plotted within the jupyter notebooks.  
- Generated results such as the trained model (.pkl) and rule files (.txt) are in the **results** directory.
- The test and train (.csv) files found in the **data** directory, are based on the output of the [pcap preprocessing notebook](./code/pcap-preprocessing.ipynb) which parses the pcap files and extracts the features needed to train the model for online deployment.

## How to Run    
- Download the CSV file for data preprocessing and offline analysis: **[link to the dataset](https://www.kaggle.com/datasets/devendra416/ddos-datasets)**</br>
Note: this CSV file is used for offline analysis but packet cature (.pcap) file are used for training and testing the application in real deployment **[link to the dataset list](./data/links-to-data.md)**

- Run the Offline Analysis Report notebook to do the following: **[link to the notebook](./code/CSCE580%20-%20Offline%20Analysis%20Report.ipynb)**
  - process the dataset
  - train and evaluate different models
  - select the best model and features for online analysis
  - build the model and generate the needed files for the online analysis

- Run the Online Deployment notebook to do the following: **[link to the notebook](./code/P4DPDK-DDoS/Online-Deployment.ipynb)**
  - build an experimental slice in FABRIC
  - setup the environment requirements
  - configure the network topology
  - run the application in hardware

## Demo [Link to demo](./doc/Demo%20Milestone%20P2%20—%20Final%20Report%20and%20Presentation.mp4)    
---