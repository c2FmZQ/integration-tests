# integration-tests

This repository contains integration tests for a system composed of `tlsproxy`, `photos`, and `ssh` services. The tests are orchestrated using `docker-compose`.

## Tests

The integration test suite includes the following tests:

*   **Photos**: Creates a new user account and logs in. The test is configured to upload a JPG image.
*   **SSO**: Verifies the Single Sign-On (SSO) flow.
*   **SSHTerm**: Navigates to the `ssh` page, generates a new SSH key, obtains a certificate from an SSH Certificate Authority, and connects to a mock SSH server.

## Running the tests

To run the tests, execute the following command:

```bash
./run-integration-tests.sh
```
