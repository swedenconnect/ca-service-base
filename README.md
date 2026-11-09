![Logo](docs/images/sweden-connect.png)

# CA Service Base

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

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

## Multiple service instances
The underlying functionality in this library is specifically designed to allow deployment on multiple 
server instances. In order to enable this in practice, the implementation of repository must support
synchronized data sharing of CA repository data as well as CRL metadata. This implementation use the
repository and metadata API:s to ensure functionality over multiple servers when synchronized storage is
used in the underlying data storage solution.

Note that the default JSON based repository provided in this library does not support synchronisation of data over multiple instances,
but the implementation provided here: [https://github.com/swedenconnect/ca-headless](https://github.com/swedenconnect/ca-headless)
implements fully synchronized storage using database support.

## Maven

Add this maven dependency to your project

```
<dependency>
    <groupId>se.swedenconnect.ca</groupId>
    <artifactId>ca-service-base</artifactId>
    <version>${ca-service-base.version}</version>
</dependency>
```

Versions up to 2.0.1 are on Maven Central. Later versions are published only to the GitHub Packages Maven registry of this repository. Using them needs a repository entry in your POM and a GitHub token, see [Using the Artifacts from GitHub Packages](docs/github-packages.md).

How to make a release is described in [Releasing](docs/release.md).

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

-----

Copyright &copy; 2022-2024, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
