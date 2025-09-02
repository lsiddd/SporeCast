# ELK Stack for Log Aggregation

This directory contains all the necessary files to deploy a full ELK stack (Elasticsearch, Logstash, Kibana) using Docker and Docker Compose. The stack is pre-configured to be secure and to receive logs from the Wazuh forwarder client.

---

## **Services Overview**

The `docker-compose.yml` file orchestrates the following services:

*   **`setup_certs`**: A temporary container that runs once to generate self-signed SSL/TLS certificates for securing communication between all stack components.
*   **`elasticsearch`**: The core search and analytics engine where logs are stored and indexed. It is configured for single-node operation with security enabled.
*   **`kibana-setup`**: A helper container that waits for Elasticsearch to be healthy and then creates a service token for Kibana to use for authentication, enhancing security.
*   **`kibana`**: The visualization platform. It provides a web UI to query and dashboard the data in Elasticsearch.
*   **`logstash`**: The data processing pipeline. It listens for incoming logs from the forwarder, processes them according to `logstash.conf`, and sends them to the secure Elasticsearch instance.

---

## **Prerequisites**

*   Docker Engine
*   Docker Compose

---

## **Configuration**

Before launching the stack, you must perform the following configuration steps:

### 1. Set the Elasticsearch Password

The Elasticsearch password must be set as an environment variable. The recommended way is to create a `.env` file in this `server` directory.

```bash
# Create a .env file from the example
cp .env.example .env
```
Now, open the `.env` file and **change the password** to a strong, secure value.

```
# .env
ELASTIC_PASSWORD=YourStrongPasswordHere
```

### 2. Update Kibana Encryption Keys

For a production setup, you **must** replace the placeholder encryption keys in `docker-compose.yml`. These keys are used by Kibana to encrypt sensitive configuration data.

In the `kibana` service definition within `docker-compose.yml`, find these environment variables and replace the placeholder values with securely generated random strings of at least 32 characters each.

```yaml
# In docker-compose.yml, under kibana > environment:
- XPACK_SECURITY_ENCRYPTIONKEY=replace_with_a_secure_random_string_32_chars
- XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=replace_with_another_secure_random_string_32_chars
- XPACK_REPORTING_ENCRYPTIONKEY=replace_with_a_third_secure_random_string_32_chars
```

---

## **Setup and Usage**

### Starting the Stack

1.  Navigate to this `server` directory in your terminal.
2.  Run the following command to build and start all services in the background:
    ```bash
    docker-compose up -d
    ```
3.  The first run may take several minutes to download the Docker images and for the services to initialize, generate certificates, and become healthy.

### Checking the Status

You can check the status and logs of the running containers:

*   **To see all running containers**: `docker-compose ps`
*   **To view the real-time logs of all services**: `docker-compose logs -f`
*   **To view the logs of a specific service (e.g., logstash)**: `docker-compose logs -f logstash`

### Accessing Services

*   **Kibana (Web UI)**:
    *   URL: `http://<your-server-ip>:5601`
    *   Username: `elastic`
    *   Password: The `ELASTIC_PASSWORD` you set in the `.env` file.

*   **Logstash (Data Ingestion)**:
    *   The Logstash service is configured to listen for TCP input on port `5140`. This is the port your client forwarder should send logs to. **Ensure this port is open in your firewall.**

### Stopping the Stack

*   To stop all running services without deleting data:
    ```bash
    docker-compose down
    ```
*   To stop services AND **delete all associated data** (this will erase all your Elasticsearch data, certificates, etc.):
    ```bash
    docker-compose down -v
    ```
