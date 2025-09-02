# SporeCast

## Security Log Aggregation and Visualization Platform

This project provides a complete, self-hosted solution for forwarding, processing, and visualizing security logs from a Wazuh agent. It consists of two main components that work together to create a powerful security monitoring pipeline.

1.  **Server**: A robust ELK (Elasticsearch, Logstash, Kibana) stack running in Docker containers. It's configured to securely receive, parse, and store logs, providing a powerful interface for analysis and visualization.
2.  **Client**: A resilient Python-based log forwarder designed to be deployed on a Wazuh server. It reliably monitors the Wazuh `alerts.json` file and sends new alerts to the ELK stack, with built-in persistence, queuing, and monitoring capabilities.

---

## **System Architecture**

The data flows from the client to the server in a simple, robust pattern:

*   **Wazuh Server (Client)**:
    *   The Wazuh agent generates security alerts, which are written to `/var/ossec/logs/alerts/alerts.json`.
    *   The `forwarder.py` script continuously monitors this file for new alerts.
    *   It sends these new alerts over a secure TCP connection to the Logstash instance on the server.

*   **ELK Stack (Server)**:
    *   **Logstash** listens for incoming connections on a specified port. It receives the JSON-formatted alerts from the client.
    *   It processes and enriches the data, then sends it to Elasticsearch.
    *   **Elasticsearch** is a powerful search and analytics engine that securely stores and indexes the log data.
    *   **Kibana** provides a web interface to explore, visualize, and create dashboards from the data stored in Elasticsearch.

---

## **Key Features**

*   **Secure Communication**: The entire ELK stack is configured with TLS/SSL encryption out-of-the-box.
*   **Containerized & Isolated**: All server components run in Docker containers, managed by Docker Compose for easy setup, scaling, and teardown.
*   **Resilient Log Forwarding**: The client script can handle network interruptions, automatically reconnecting with exponential backoff.
*   **Persistent State**: The client saves its reading position, ensuring no logs are lost or duplicated across restarts or log rotations.
*   **In-Memory Buffering**: The client queues logs if the server is unreachable, preventing data loss during network downtime.
*   **Real-time Monitoring**: Optional Telegram integration provides status updates, connection alerts, and heartbeats from the forwarder script.

---

## **Getting Started**

To get the full system running, you must set up the server first, then the client.

1.  **Setup the Server**: Begin by deploying the ELK stack. Follow the detailed instructions in the [Server README](./server/README.md).
2.  **Setup the Client**: Once the server is running and accessible, deploy the Python forwarder on your Wazuh machine. Follow the detailed instructions in the [Client README](./client/README.md).

---

## **Directory Structure**

```
.
├── client/
│   ├── forwarder.py              # The Python log forwarder script.
│   ├── wazuh-forwarder.service   # systemd service file for the forwarder.
│   └── README.md                 # Detailed setup instructions for the client.
│
├── server/
│   ├── docker-compose.yml        # Defines and configures all ELK stack services.
│   ├── logstash.conf             # Logstash pipeline configuration for parsing logs.
│   ├── .env.example              # Example environment file for credentials.
│   ├── kibana-setup/
│   │   └── Dockerfile            # Dockerfile for a helper container to generate Kibana token.
│   └── README.md                 # Detailed setup instructions for the server.
│
└── README.md                     # This file (Project Overview).
```
