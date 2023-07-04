# Crypto
Crypto is a service that acts as a proxy to the Vault KeyValue store. 
It will be able to create and store private keys, CSRs and sign content based on private keys from the Vault.
It should be replaceable by a product like an (AWS) HSM, so it should not have custom endpoints or have any Yolt domain knowledge.
 
## How it interacts with Vault and Kubernetes
We have created a Kubernetes Service Account for this service, called "crypto". This has read/list/write permissions on certain paths in Vault. 
The Service Account is linked to the Deployment of the crypto application. Kubernetes will then mount the Service Account Token into the pod on ``/var/run/secrets/kubernetes.io/serviceaccount/token``.
The Spring Vault library will pick up that Service Account Token and use it for authenticating to Vault. Vault will verify that token by calling Kubernetes. When it succeeds it will return a Vault Token.
The Vault Token can be used to read/list/write secrets on Vault and is valid for a minimal time. The Spring Vault library takes care of renewing the Vault Token.

## Running it locally
The application can be run as a regular Spring Boot application with a profile like 'local-team4'.
A file should be created under ``/var/run/secrets/kubernetes.io/serviceaccount/token`` which should be populated with a valid Service Account Token for team4, default namespace.
Alternatively you can create an environment variable ``YOLT_VAULT_AUTH_SERVICE_ACCOUNT_TOKEN_FILE`` including the path to the token file.

The Service Account Token can be retrieved by fetching the crypto-token-{xxxxx} secret and then reading the (base64 decoded) ``token`` field. 
 
## Context diagram
![context diagram](https://git.yolt.io/pages/backend-tools/yolt-architecture-diagram/downloaded-architecture-diagrams/crypto.puml.svg?job=build)  
[source](https://git.yolt.io/backend-tools/yolt-architecture-diagram/)
