# Contributing to PhishShield AI

We welcome contributions to PhishShield AI! To help maintain code quality, security, and performance, please follow these guidelines:

## Code of Conduct

Please be respectful and professional in all communications and collaborations.

## How to Contribute

1.  **Search Issues**: Check if a similar issue or pull request already exists before starting work.
2.  **Fork & Branch**: Fork the repository and create your branch from `main`:
    ```bash
    git checkout -b feature/my-new-threat-module
    ```
3.  **Implement Tests**: Any new security checkers or helper functions must include corresponding assertions inside the `tests/` directory.
4.  **Verify & Test**: Run the test suite before submitting:
    ```bash
    npm test
    ```
5.  **Submit PR**: Describe your changes in detail, explaining the security rationale behind your code modifications.

## Style Guidelines

*   **ES Modules**: Use modern, standards-compliant ES module syntax (`import`/`export`).
*   **Logging**: Utilize the custom `logger` interface in `utils.js` instead of plain `console.log`.
*   **Performance**: Avoid adding heavy external npm dependencies to keep the extension footprint small and lightweight.
