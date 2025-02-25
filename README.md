# One-Do-Three

## Overview
One-Do-Three is a Rust-based application designed for secure task management, manage user authentication, encryption, and email authentication efficiently. It provides modular components for security, task tracking, and user management.

## Features
- **User Authentication**: Secure user login, password management, and token-based authentication.
- **Encryption**: Utilizes cryptographic functions for secure data handling.
- **Task Management**: Track, store, and update tasks.
- **Email Integration**: SMTP setup for notifications and email templates.
- **Logging & Utilities**: Provides structured logging and time management utilities.

## Installation
### Prerequisites
- Rust (latest stable version)
- Cargo package manager

### Steps
1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/one-do-three.git
   cd one-do-three
   ```
2. Install dependencies:
   ```sh
   cargo build
   ```
3. Run the application:
   ```sh
   cargo run
   ```

## Configuration
Edit the `Config` files located in `src/modules/admin/config.rs` to set up authentication, encryption, and email settings.

## Modules Breakdown
### Authentication (`src/modules/auth`)
- Handles user authentication, password management, token generation, and verification.

### Encryption (`src/modules/encryption`)
- Implements cryptographic functions and key management for secure data.

### Email Management (`src/modules/email`)
- Configures SMTP email setup and manages email templates.

### Task Management (`src/modules/tasks`)
- Allows users to create, track, and update tasks.

### Security (`src/modules/security`)
- Manages keyrings and security configurations.

### Utilities (`src/modules/utils`)
- Provides logging, time management, and input/output utilities.

## Usage
1. Register a user and log in.
2. Add, edit, delete, visualise and track tasks.
3. Manage user profile.

## Contributing
1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch`.
3. Commit changes: `git commit -m 'Add feature'`.
4. Push to the branch: `git push origin feature-branch`.
5. Open a Pull Request.

## License
This project is licensed under the MIT License.

## Contact
For issues and inquiries, open an issue on GitLab or contact the maintainer at `amir.madvi.sabet@gmail.com`.

---
Enjoy using One-Do-Three!

