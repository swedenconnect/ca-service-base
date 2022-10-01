![Logo](docs/images/sweden-connect.png)

# CA Service Base

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.ca/ca-service-base/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.ca/ca-service-base)

This repository provides the core classes for a Spring Boot application that implements CA services
based on the following base libraries:

- [https://github.com/swedenconnect/ca-engine](https://github.com/swedenconnect/ca-engine)
- [https://github.com/swedenconnect/ca-cmc](https://github.com/swedenconnect/ca-cmc)

The CA services functionality provided by this repository provides the basic beans and controllers that
implements the following functionality:

- Service configuration structure for the CA services application
- CRL distribution controller
- OCSP responder controller
- CMC API support for CMC based clients and registration authorities.
- CA Audit logging
- CA service health check
- Basic error handling
- Basic CA service implementation

-----
## Documentation

---

A complete CA services application can be built using this code as a base but extending it in the following way:

- Implement the CA service by extending the abstract implementations provided by this project
- Provide a suitable CA repository implementation
- Extend health indication
- Extend audit logging

Examples of this are provided in the following code projects:

- [https://github.com/swedenconnect/ca-headless](https://github.com/swedenconnect/ca-headless)
- [https://github.com/swedenconnect/ca-signservice](https://github.com/swedenconnect/ca-signservice)