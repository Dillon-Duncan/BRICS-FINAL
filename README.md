# Brics Banking Application

## Overview

Brics Banking is a full-stack web application designed to manage user accounts and transactions. The application is built using React for the frontend and Node.js with Express for the backend. MongoDB is used as the database to store user and transaction data.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Available Scripts](#available-scripts)
- [API Endpoints](#api-endpoints)
  - [User Endpoints](#user-endpoints)
  - [Transaction Endpoints](#transaction-endpoints)
- [Dependencies](#dependencies)
  - [Frontend](#frontend)
  - [Backend](#backend)
- [Contributing](#contributing)
- [License](#license)

---

## Getting Started

To get started with the Brics Banking application, follow these steps:

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Dillon-Duncan/brics-banking.git
   cd brics-banking
   ```

2. **Install dependencies for both the frontend and backend:**

   ```bash
   npm install
   cd backend
   npm install
   cd ..
   ```

3. **Start the backend server:**

   ```bash
   cd backend
   npm start
   ```

4. **Start the frontend development server:**

   ```bash
   cd ..
   npm start
   ```

5. Open [http://localhost:3000](http://localhost:3000) to view the application in your browser.

---

## Project Structure

The project structure is as follows:

```plaintext
brics-banking/
├── backend/
│   ├── src/
│   │   ├── configuration/
│   │   │   └── dbConfig.js
│   │   ├── controllers/
│   │   │   ├── transactionController.js
│   │   │   └── userController.js
│   │   ├── models/
│   │   │   ├── transaction.js
│   │   │   └── user.js
│   │   ├── routes/
│   │   │   ├── transactionRoutes.js
│   │   │   └── userRoutes.js
│   │   ├── services/
│   │   │   ├── transactionService.js
│   │   │   └── userService.js
│   ├── index.js
│   └── package.json
├── public/
│   ├── index.html
│   ├── manifest.json
│   └── robots.txt
├── src/
│   ├── components/
│   │   ├── admin/
│   │   │   ├── dashboard/
│   │   │   │   ├── adminApprove.js
│   │   │   │   ├── adminDashboard.js
│   │   │   │   └── adminHistory.js
│   │   │   └── login/
│   │   │       └── adminLogin.js
│   │   ├── header/
│   │   │   ├── header.js
│   │   │   └── header.css
│   │   ├── nomatch/
│   │   │   └── noMatch.js
│   │   ├── user/
│   │   │   ├── dashboard/
│   │   │   │   ├── history/
│   │   │   │   │   └── userHistory.js
│   │   │   │   ├── transaction/
│   │   │   │   │   └── userTransaction.js
│   │   │   │   └── userDashboard.js
│   │   │   ├── login/
│   │   │   │   └── userLogin.js
│   │   │   └── register/
│   │   │       └── userRegister.js
│   ├── App.css
│   ├── App.js
│   ├── App.test.js
│   ├── index.css
│   ├── index.js
│   ├── reportWebVitals.js
│   └── setupTests.js
├── .gitignore
├── README.md
├── package.json
└── yarn.lock
```

---

## Available Scripts

In the project directory, you can run:

- `npm start`: Runs the frontend app in development mode. Open [http://localhost:3000](http://localhost:3000) to view it in your browser. The page will reload when you make changes, and you may also see lint errors in the console.
  
- `npm test`: Launches the test runner in interactive watch mode. See the section about running tests for more information.

- `npm run build`: Builds the app for production to the `build` folder. It bundles React in production mode and optimizes the build for the best performance. The build is minified, and filenames include hashes.

- `npm run eject`: **Note**: This is a one-way operation. Once you eject, you can't go back! If you're not satisfied with the build tool and configuration choices, you can eject at any time. This command will remove the single build dependency from your project and copy all configuration files and dependencies into your project for full control.

- `npm run backend`: Runs the backend server. Open [http://localhost:5000](http://localhost:5000) to view the backend API.

---

## API Endpoints

### User Endpoints

- `POST /api/users`: Create a new user.
- `GET /api/users/:accountNumber`: Get a user by account number.
- `GET /api/users/usersAll`: Get all users.
- `PUT /api/users/:accountNumber`: Update a user by account number.
- `DELETE /api/users/:accountNumber`: Delete a user by account number.
- `POST /api/users/login`: Login a user.
- `POST /api/users/register`: Register a new user.

### Transaction Endpoints

- `POST /api/transactions`: Create a new transaction.
- `GET /api/transactions`: Get all transactions.
- `GET /api/transactions/user/:accountNumber`: Get transactions by account number.
- `GET /api/transactions/user/:accountNumber/latest`: Get the latest 5 transactions for a specific user.
- `GET /api/transactions/latest`: Get the latest 5 transactions across all users.
- `GET /api/transactions/pending`: Get transactions with pending status.
- `GET /api/transactions/:id`: Get a single transaction by ID.
- `PUT /api/transactions/:id`: Update a transaction by ID.
- `PUT /api/transactions/:id/status`: Update the status of a transaction by ID.
- `DELETE /api/transactions/:id`: Delete a transaction by ID.

---

## Dependencies

### Frontend

- `axios`: Promise-based HTTP client for the browser and Node.js.
- `bootstrap`: The most popular CSS framework.
- `react`: A JavaScript library for building user interfaces.
- `react-bootstrap`: Bootstrap components built with React.
- `react-dom`: Serves as the entry point to the DOM and server renderers for React.
- `react-router-dom`: DOM bindings for React Router.
- `react-scripts`: Scripts and configuration used by Create React App.
- `web-vitals`: A library for measuring web performance.

### Backend

- `bcryptjs`: Library to hash passwords.
- `cors`: Middleware to enable CORS.
- `express`: Fast, unopinionated, minimalist web framework for Node.js.
- `mongoose`: MongoDB object modeling tool designed to work in an asynchronous environment.

---

## Contributing

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch`.
3. Make your changes.
4. Commit your changes: `git commit -m 'Add some feature'`.
5. Push to the branch: `git push origin feature-branch`.
6. Open a pull request.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.
