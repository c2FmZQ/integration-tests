# Integration Tests

This repository contains integration tests for a system composed of `tlsproxy`, `photos`, and `sshterm` services. The tests are orchestrated using `docker compose`.

## Architecture

The following diagram shows the architecture of the integration test environment:

```mermaid
graph TD
    subgraph "Docker Compose"
        A[devtests]
        B["headless-shell (chrome)"];
        P((tlsproxy));
        subgraph "External Services"
            S1[acme-server];
            S2[mock-oidc-server];
            S3[mock-ssh-server];
        end
        subgraph "Backends"
            B1[photos-backend];
            B2[c2fmzq.org];
            B3[sshterm];
            B4[mock-backend];
            B5[pki]
        end
    end

    A -->|DevTools Protocol| B;
    B -->|HTTPS| P;
    A -->|HTTPS| P;
    P -->|"ACME"| S1;
    P -->|"OpenID Connect"| S2;
    P -->|"WebSocket Proxy (TCP)"| S3;
    S3 -->|"HTTPS (Get CA cert)"| P;
    P -->|HTTP Backend| B1;
    P -->|static content| B2;
    P -->|static content| B3;
    P -->|HTTPS Backend| B4;
    B4 -->|"HTTPS (Get JWKS)"| P
    P -->|Local Backend| B5;

    style S1 fill:#eee,stroke:#333,stroke-width:2px
    style S2 fill:#eee,stroke:#333,stroke-width:2px
    style S3 fill:#eee,stroke:#333,stroke-width:2px
    style A fill:#f9f,stroke:#333,stroke-width:2px
    style B fill:#ccf,stroke:#333,stroke-width:2px
    style P fill:#cfc,stroke:#333,stroke-width:2px
    style B1 fill:#ffc,stroke:#333,stroke-width:2px
    style B2 fill:#ffc,stroke:#333,stroke-width:2px
    style B3 fill:#ffc,stroke:#333,stroke-width:2px
    style B4 fill:#ffc,stroke:#333,stroke-width:2px
    style B5 fill:#ffc,stroke:#333,stroke-width:2px
```

The services are:

*   **`devtests`**: The main test container that runs the integration tests written in Go.
*   **`headless-shell`**: A headless Chrome browser used to perform UI tests.
*   **`tlsproxy`**: A TLS proxy that provides HTTPS termination, OIDC authentication, and routing to the backend services.
*   **`mock-oidc-server`**: A mock OIDC server for testing authentication.
*   **`mock-ssh-server`**: A mock SSH server for testing `sshterm`.
*   **`acme-server`**: An in-memory ACME server for testing certificate issuance.
*   **`photos-backend`**: The backend for the photos application.
*   **`c2fmzq.org`**: The c2fmzq.org website, served as static content.
*   **`sshterm`**: A web-based SSH terminal, served as static content by the `tlsproxy` service.
*   **`mock-backend`**: A mock backend running TLSPROXY's example backend.

## Tests

The integration test suite includes the following tests:

*   **Photos**: Creates a new user account in the photos application, logs in, and uploads a JPG image.
*   **SSO**: Verifies the Single Sign-On (SSO) flow with the mock OIDC server.
*   **SSHTerm**: Navigates to the `sshterm` page, generates a new SSH key, obtains a certificate from an SSH Certificate Authority, and connects to the mock SSH server.
*   **PKI**: Navigates to the PKI endpoint, generates an ECDSA key and a X.509 certificate, and uses them for client authentication.

## Prerequisites

To run the tests, you need to have Docker installed and configured to run without `sudo`. You can add your user to the `docker` group with the following command:

```bash
sudo usermod -aG docker ${USER}
```

After running this command, you will need to log out and log back in for the changes to take effect.

## Running the tests

To run the tests, execute the following command:

```bash
./run-integration-tests.sh
```

This script will:

1.  Clone the required git repositories for `tlsproxy`, `photos`, and `sshterm`.
2.  Build the necessary Docker images.
3.  Run the integration tests using `docker compose`.
