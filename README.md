# BLESS Web Ingress

This project provides a web ingress for accessing the BLESS P2P network. It allows users to get results, use easy names, and perform subdomain routing for execution.

## Features

- **Web Entry**: Provides a web interface to interact with the BLESS P2P network.
- **Easy Names**: Simplifies access using easy-to-remember names instead of CIDs
- **Subdomain Routing**: Supports routing based on subdomains for different executions.

## Getting Started

### Prerequisites

- Go 1.18 or later
- Docker (optional, for containerized deployment)

### Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/bless-web-ingress.git
    cd bless-web-ingress
    ```

2. Copy the example environment file and update it with your configuration:
    ```sh
    cp example.env .env
    ```

3. Build the project:
    ```sh
    go build -o bless-web-ingress main.go
    ```

4. Run the executable:
    ```sh
    ./bless-web-ingress
    ```

### Usage

Once the server is running, you can access the web interface at `http://localhost:8080`. Use the interface to interact with the BLESS P2P network, get results, and manage subdomain routing.

### Return Types

The system supports different return types for the responses. You can specify the return type when inserting or updating a host. The supported return types are:

- **text**: Returns the response as plain text.
- **json**: Returns the response as JSON.
- **html**: Returns the response as HTML.
- **raw**: Returns the raw response from the external API.

### Short Names Generation

Short names are generated to simplify access to resources within the BLESS P2P network. Instead of using long and complex CIDs (Content Identifiers), the system generates easy-to-remember names. This is achieved by mapping each CID to a unique short name, which can then be used for quick access and routing.

#### Technical Details

1. **Hashing**: The CID is hashed using a consistent hashing algorithm to ensure uniqueness.
2. **Encoding**: The hashed value is then encoded into a shorter, human-readable format.
3. **Mapping**: This encoded value is stored in a database along with the original CID for quick lookup.
4. **Retrieval**: When a short name is used, the system retrieves the corresponding CID from the database and processes the request.

### Updating Names

The `/update` endpoint allows updating the destination of an existing host. This endpoint requires the `updater_id` to match the existing `updater_id` of the host. If the `updater_id` matches, the destination and return type can be updated.

#### Example Request

```sh
curl -X POST http://localhost:8080/update -H "Content-Type: application/json" -d '{
  "host": "example-host",
  "destination": "bafynewdestination",
  "updater_id": "existing-updater-id",
  "return_type": "json"
}'
```

#### Response

- **200 OK**: If the update is successful.
- **400 Bad Request**: If the request is malformed or missing required fields.
- **403 Forbidden**: If the `updater_id` does not match the existing `updater_id` of the host.
- **404 Not Found**: If the host does not exist.
- **500 Internal Server Error**: If there is an error updating the host.

### Publishing CIDs to IPFS

CIDs (Content Identifiers) need to be published to IPFS outside of this application. This application does not handle the publishing of CIDs to IPFS. Ensure that your content is available on the IPFS network before attempting to use it with this application.

### Node Execution and BLESS RPC

Node execution requires a BLESS RPC for execution requests. The BLESS RPC endpoint must be configured to handle execution requests and return the appropriate results. Ensure that your BLESS RPC endpoint is properly set up and accessible by this application.

#### Example BLESS RPC Request

```json
{
  "function_id": "bafyexamplecid",
  "method": "execute",
  "parameters": null,
  "config": {
    "permissions": [],
    "env_vars": [
      {
        "name": "BLS_REQUEST_PATH",
        "value": "/api"
      }
    ],
    "number_of_nodes": 1
  }
}
```

## Contributing

The `main.go` file is the entry point of the application. It sets up the web server, handles routing, and integrates with the BLESS P2P network. Key functionalities include:

- Setting up HTTP routes for web access.
- Handling subdomain routing.
- Interfacing with the BLESS P2P network to fetch and display results.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.