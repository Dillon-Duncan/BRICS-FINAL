const express = require('express');
const TransactionController = require('../controllers/transactionController');

const router = express.Router();

// Route to create a new transaction
router.post('/', TransactionController.createTransaction);

// Route to get all transactions
router.get('/', TransactionController.getTransactions);

// Route to get transactions by account number
router.get('/user/:accountNumber', TransactionController.getTransactionsByAccountNumber);

// Route to get the latest 5 transactions for a specific user
router.get('/user/:accountNumber/latest', TransactionController.getLatestTransactionsForUser);

// Route to get the latest 5 transactions across all users
router.get('/latest', TransactionController.getLatestTransactions);

// Route to get transactions with pending status
router.get('/pending', TransactionController.getPendingTransactions);

// Route to get a single transaction by ID
router.get('/:id', TransactionController.getTransactionById);

// Route to update a transaction by ID
router.put('/:id', TransactionController.updateTransaction);

// Route to update the status of a transaction by ID
router.put('/:id/status', TransactionController.updateTransactionStatus);

// Route to delete a transaction by ID
router.delete('/:id', TransactionController.deleteTransaction);

module.exports = router;
