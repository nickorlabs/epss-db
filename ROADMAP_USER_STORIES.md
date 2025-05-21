# ExploitPulse Roadmap: User Stories by Phase

This document outlines the major phases of the ExploitPulse (epss-fork) project improvement plan, broken down into actionable user stories suitable for tracking on GitHub.

---

## Phase 1: Security Hardening

- **As a developer, I want to store database credentials in Docker secrets or a secure secrets manager, so that sensitive information is not exposed in code or environment variables.**
- **As a maintainer, I want all Python dependencies to have pinned versions in requirements.txt, so that builds are reproducible and supply chain risks are minimized.**
- **As an operator, I want all error logs to be sanitized, so that sensitive data and stack traces are not leaked in production logs.**

---

## Phase 2: Reliability & Data Integrity

- **As a developer, I want all ETL scripts to have robust error handling and logging, so that failures are visible and actionable.**
- **As a user, I want the system to retry network and database operations on transient errors, so that temporary issues do not cause data loss.**
- **As a developer, I want all Python functions to have type hints and the codebase to pass type checking, so that bugs are caught early and the code is easier to maintain.**
- **As a data engineer, I want fields like references to be normalized in the database schema, so that data is easier to query and maintain.**

---

## Phase 3: Maintainability & Performance

- **As a developer, I want shared configuration and utility logic to be refactored into common modules, so that code is not duplicated across ETL scripts (DRY principle).**
- **As an operator, I want ETL jobs to be capable of running in parallel where safe, so that large data imports complete faster.**
- **As a maintainer, I want all temporary files and resources to be reliably cleaned up, even on error, so that disk usage remains under control.**

---

## Phase 4: Optional/Advanced Enhancements

- **As a maintainer, I want static analysis and security linting (e.g., bandit, pylint, black) to run automatically in CI/CD, so that code quality and security are continuously enforced.**
- **As a developer, I want comprehensive unit and integration tests for ETL scripts, so that regressions and edge cases are caught before release.**
- **As a team, I want to measure and track code coverage, so that we can ensure our tests are effective.**

---

## Phase 5: Frontend Web Application for Data Exploration

- **As a security analyst, I want a web dashboard where I can search, filter, and browse CVEs, EPSS scores, KEV, and exploit data, so that I can quickly find relevant vulnerabilities.**
- **As a user, I want to visualize vulnerability trends over time with charts and graphs, so that I can spot patterns and prioritize risks.**
- **As a user, I want to export search results as CSV or JSON, so that I can use the data in external tools.**
- **As a developer, I want a REST or GraphQL API that exposes queryable vulnerability data, so that the frontend and external tools can access data efficiently.**
- **As an admin, I want the frontend and API to be containerized and secured (HTTPS, authentication if needed), so that deployment is easy and safe.**
- **As a contributor, I want clear documentation for using, deploying, and extending the frontend, so that others can participate in the project.**

---

*This document is intended for sharing on GitHub to guide contributors and track progress. Each user story can be converted into a GitHub issue or project board item.*
