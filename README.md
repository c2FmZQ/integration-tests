# integration-tests

This repository contains integration tests for a system composed of `tlsproxy`, `photos`, and `ssh` services. The tests are orchestrated using `docker-compose`.

## Tests

The integration test suite includes the following tests:

*   **Photos**: Creates a new user account and logs in. The test is currently configured to upload a PNG image, but this functionality is not working correctly.
*   **SSHTerm**: Navigates to the `ssh` page, generates a new SSH key, obtains a certificate from an SSH Certificate Authority, and connects to a mock SSH server. This test is currently commented out.
*   **SSO**: Verifies the Single Sign-On (SSO) flow. This test is currently commented out.

## Running the tests

To run the tests, execute the following command:

```bash
./run-integration-tests.sh
```
