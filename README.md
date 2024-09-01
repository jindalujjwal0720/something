# Something

A production ready project structure for MERN stack applications.

## Features

- **Technology Stack**: MERN (MongoDB, Express, React, Node.js)
- **Authentication**: JWT based authentication
- **Authorization**: Role based access control (RBAC) with permission policies
- **Database**: MongoDB with Mongoose ODM
- **ESLint**: Fully configured ESLint in both backend and frontend
- **Prettier**: Prettier is configured in both backend and frontend
- **Environment Variables**: Environment variables are configured in both backend and frontend
- **Error Handling**: Centralized error handling in backend with custom error classes and middleware
- **Security**: Security best practices with HTTP headers and `helmet`
- **Compression**: Gzip compression with `compression`
- **TypeScript**: TypeScript support in both backend and frontend
- **Logging**: Winston logger is configured in backend
- **Testing**: Vitest for frontend and Jest for backend are fully configured
- **Storybook**: Storybook is configured in frontend for UI component development

## Stories

### **General**

| **Story**                                                                                                 | **Feature**                                     |
| --------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| As a user, I want to be able to register to the app                                                       | User registration                               |
| As a user, I want to receive a confirmation email after registration                                      | Email verification                              |
| As a user, I want to be notified if my registration is unsuccessful                                       | Registration error handling                     |
| As a user, I want to log in to my account                                                                 | User login                                      |
| As a user, I want to be notified if my login attempt is unsuccessful                                      | Login error handling                            |
| As a user, I want to be able to receive a reset password link                                             | Password reset - link generation                |
| As a user, I want to be able to change my password from the reset link                                    | Password reset - link-based password change     |
| As a user, I want to be able to change my password using my current password                              | Password change - current password verification |
| As a user, I want to be notified if my password change is unsuccessful                                    | Password change error handling                  |
| As a user, I want to receive an email confirmation when my password is changed                            | Password change confirmation                    |
| As a user, I want to log out of my account                                                                | User logout                                     |
| As a user, I want to be able to log out from all devices                                                  | Logout from all devices                         |
| As a user, I want to receive a confirmation email when I log out                                          | Logout confirmation                             |
| As a user, I want to be able to update my account information                                             | Account management                              |
| As a user, I want to update my profile picture                                                            | Profile picture update                          |
| As a user, I want to update my contact information (e.g., phone number)                                   | Contact information update                      |
| As a user, I want to be notified if my account update is unsuccessful                                     | Account update error handling                   |
| As a user, I want to enable two-factor authentication for added security                                  | Two-factor authentication (2FA)                 |
| As a user, I want to configure my 2FA settings (e.g., app or SMS)                                         | 2FA configuration                               |
| As a user, I want to receive a backup code for 2FA                                                        | 2FA backup codes                                |
| As a user, I want to view my login history                                                                | Login history                                   |
| As a user, I want to search and filter my login history by date or device                                 | Login history filtering and search              |
| As a user, I want to see details of my last login (e.g., location, device)                                | Login details                                   |
| As a user, I want to ensure that my authentication data is encrypted and secure                           | Data encryption and security                    |
| As a user, I want to receive alerts if there are any suspicious activities on my account                  | Security alerts                                 |
| As a user, I want to be able to recover my account if I forget my password                                | Account recovery                                |
| As a user, I want to verify my identity through an alternative method if I cannot access my primary email | Alternative identity verification               |
| As a user, I want to be able to view and manage my authorized devices                                     | Device management                               |
| As a user, I want to remove unauthorized devices from my account                                          | Device removal                                  |
| As a user, I want to receive notifications for suspicious login attempts                                  | Security notifications                          |
| As a user, I want to be able to verify my account through SMS or email                                    | Multi-channel verification options              |
| As a user, I want to choose my preferred verification method (SMS or email)                               | Verification method selection                   |
| As a user, I want to be able to update my email address linked to my account                              | Email update                                    |
| As a user, I want to receive a confirmation email when my email is updated                                | Email update confirmation                       |
| As an admin, I want to manage user accounts and permissions                                               | Admin management                                |
| As an admin, I want to view and manage user roles and permissions                                         | User roles and permissions management           |
| As an admin, I want to deactivate or delete user accounts                                                 | Account deactivation and deletion               |
| As an admin, I want to view system logs for authentication activities                                     | System logging                                  |
| As an admin, I want to generate reports on authentication activities                                      | Authentication activity reports                 |

Certainly! Here’s a more detailed breakdown of the remaining features:

### **Password Reset**

| **Story**                                                                                  | **Feature**                                     |
| ------------------------------------------------------------------------------------------ | ----------------------------------------------- |
| As a user, I want to be able to request a password reset link via email                    | Password reset - link generation                |
| As a user, I want to receive a password reset link within a specified timeframe            | Password reset link expiration                  |
| As a user, I want to be able to change my password from the link provided                  | Password reset - link-based password change     |
| As a user, I want to be able to change my password using my current password               | Password change - current password verification |
| As a user, I want to be notified if my password reset request fails                        | Password reset error handling                   |
| As a user, I want to receive a confirmation email when my password is successfully changed | Password change confirmation                    |
| As a user, I want to be able to request another reset link if the first one expires        | Request new reset link                          |

### **Login History**

| **Story**                                                                                    | **Feature**                        |
| -------------------------------------------------------------------------------------------- | ---------------------------------- |
| As a user, I want to view my login history                                                   | Login history                      |
| As a user, I want to see details of each login attempt (e.g., timestamp, IP address, device) | Login attempt details              |
| As a user, I want to filter and search my login history by date, device, or location         | Login history filtering and search |
| As a user, I want to receive notifications about unusual login attempts                      | Login attempt notifications        |

### **Security Notifications**

| **Story**                                                                                               | **Feature**                     |
| ------------------------------------------------------------------------------------------------------- | ------------------------------- |
| As a user, I want to receive notifications for suspicious activities                                    | Security notifications          |
| As a user, I want to receive an alert if my account is accessed from an unrecognized device or location | Suspicious activity alerts      |
| As a user, I want to be notified if my account settings are changed (e.g., email, password)             | Account change notifications    |
| As a user, I want to receive alerts if my 2FA method is updated                                         | 2FA method change notifications |

### **Device Management**

| **Story**                                                                                     | **Feature**                     |
| --------------------------------------------------------------------------------------------- | ------------------------------- |
| As a user, I want to view a list of devices authorized to access my account                   | Authorized devices list         |
| As a user, I want to remove any devices that I no longer use or recognize                     | Device removal                  |
| As a user, I want to receive notifications when a new device is authorized                    | New device authorization alerts |
| As a user, I want to see details of each authorized device (e.g., device type, last activity) | Device details                  |

### **Admin Management**

| **Story**                                                                                        | **Feature**                           |
| ------------------------------------------------------------------------------------------------ | ------------------------------------- |
| As an admin, I want to manage user accounts and permissions                                      | Admin management                      |
| As an admin, I want to view and update user roles and permissions                                | User roles and permissions management |
| As an admin, I want to deactivate or delete user accounts                                        | Account deactivation and deletion     |
| As an admin, I want to view detailed logs of user activities and authentication events           | Admin activity logs                   |
| As an admin, I want to generate and export reports on authentication activities and system usage | Reporting and analytics               |

### **Data Encryption and Security**

| **Story**                                                                                        | **Feature**                  |
| ------------------------------------------------------------------------------------------------ | ---------------------------- |
| As a user, I want to ensure my authentication data is encrypted during transmission and storage  | Data encryption              |
| As a user, I want to be assured that my personal information is stored securely                  | Secure data storage          |
| As a user, I want to receive information about how my data is protected                          | Data protection transparency |
| As a user, I want to be informed of any data breaches or security incidents involving my account | Data breach notifications    |

### **Multi-Channel Verification**

| **Story**                                                                            | **Feature**                        |
| ------------------------------------------------------------------------------------ | ---------------------------------- |
| As a user, I want to verify my account through SMS or email                          | Multi-channel verification options |
| As a user, I want to choose my preferred verification method (SMS or email)          | Verification method selection      |
| As a user, I want to update my verification preferences                              | Verification preferences update    |
| As a user, I want to receive a backup verification method if my primary method fails | Backup verification method         |

### **Account Management**

| **Story**                                                                             | **Feature**                        |
| ------------------------------------------------------------------------------------- | ---------------------------------- |
| As a user, I want to be able to update my account information                         | Account management                 |
| As a user, I want to update my profile picture                                        | Profile picture update             |
| As a user, I want to update my contact information (e.g., phone number)               | Contact information update         |
| As a user, I want to update my email address linked to my account                     | Email address update               |
| As a user, I want to receive a confirmation email when my email is updated            | Email update confirmation          |
| As a user, I want to update my password and receive a confirmation email              | Password update confirmation       |
| As a user, I want to view my account activity and recent changes                      | Account activity log               |
| As a user, I want to manage linked accounts and services (e.g., OAuth)                | Linked accounts management         |
| As a user, I want to set and update my security questions for account recovery        | Security questions setup           |
| As a user, I want to be able to deactivate or delete my account                       | Account deactivation and deletion  |
| As a user, I want to receive a confirmation when my account is deactivated or deleted | Account deletion confirmation      |
| As a user, I want to contact support if I encounter issues with account management    | Support contact for account issues |

### **Two-Factor Authentication (2FA)**

| **Story**                                                                                            | **Feature**                     |
| ---------------------------------------------------------------------------------------------------- | ------------------------------- |
| As a user, I want to enable two-factor authentication (2FA) for added security                       | Two-factor authentication (2FA) |
| As a user, I want to configure my 2FA settings, such as choosing between SMS or an authenticator app | 2FA configuration               |
| As a user, I want to receive a one-time password (OTP) via SMS or email for 2FA verification         | 2FA OTP delivery                |
| As a user, I want to set up and use an authenticator app (e.g., Google Authenticator) for 2FA        | Authenticator app setup         |
| As a user, I want to view and manage my list of backup codes for 2FA                                 | 2FA backup codes management     |
| As a user, I want to disable 2FA if I no longer wish to use it                                       | 2FA disablement                 |
| As a user, I want to receive a notification when 2FA is enabled or disabled                          | 2FA status notifications        |
| As a user, I want to be able to recover my 2FA settings if I lose access to my authentication method | 2FA recovery process            |
| As a user, I want to be able to update my 2FA method (e.g., switch from SMS to an authenticator app) | 2FA method update               |
| As a user, I want to be guided through the 2FA setup process with clear instructions                 | 2FA setup instructions          |

### **One-Click Login for Trusted Devices**

| Story                                                                                 | Feature                             |
| ------------------------------------------------------------------------------------- | ----------------------------------- |
| As a user, I want to log in with a single click on devices I have previously verified | One-click login for trusted devices |
| As a user, I want to manage and review trusted devices from my account settings       | Trusted devices management          |

### **Account Recovery**

| Story                                                                                      | Feature                           |
| ------------------------------------------------------------------------------------------ | --------------------------------- |
| As a user, I want to be able to recover my account if I forget my password                 | Account recovery                  |
| As a user, I want to verify my identity through an alternative method if I forget my email | Alternative identity verification |

## Getting Started

### Prerequisites

- Node.js (v18+)
- MongoDB
- Git
- VSCode (recommended)

### Installation

1. Create a new directory and navigate to it

2. Clone the repository and remove the `.git` directory to start fresh

```bash
git clone https://jindalujjwal0720/something.git . && rm -rf .git && git init
```

3. Install the dependencies in both server and web

```bash
cd server && npm install && cd ../web && npm install && cd ..
```

4. Create `.env` files in both server and web by copying the `.env.example` files

```bash
cp server/.env.example server/.env && cp web/.env.example web/.env
```

5. Start the development server in both server and web (in separate terminals)

```bash
cd server
npm run dev
```

```bash
cd web
npm run dev
```

6. Open the browser and navigate to `http://localhost:3000`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## References

- [Bulletproof Node.js Project Architecture](https://softwareontheroad.com/ideal-nodejs-project-structure/)
- [Bulletproof React Project Architecture](https://softwareontheroad.com/ideal-react-project-structure/)

- [Node.js](https://nodejs.org/)
- [MongoDB](https://www.mongodb.com/)
- [Express](https://expressjs.com/)
- [React](https://reactjs.org/)
- [Winston Logger](https://github.com/winstonjs/winston#readme)
- [Helmet](https://helmetjs.github.io/)
