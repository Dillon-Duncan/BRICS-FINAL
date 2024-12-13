const TransactionService = require('../services/transactionService');
const Transaction = require('../models/transaction');

class TransactionController {
  /**
   * Create a new transaction.
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   */
  async createTransaction(req, res) {
    try {
      console.log('Request body:', req.body); // Log the request body
      const newTransaction = await TransactionService.createTransaction(req.body);
      res.status(201).json(newTransaction);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  /**
   * Get all transactions.
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   */
  async getTransactions(req, res) {
    try {
      const transactions = await TransactionService.getTransactions();
      res.status(200).json(transactions);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get a single transaction by ID.
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   */
  async getTransactionById(req, res) {
    try {
      const { id } = req.params;
      const transaction = await TransactionService.getTransactionById(id);
      if (!transaction) {
        return res.status(404).json({ error: 'Transaction not found' });
      }
      res.status(200).json(transaction);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get the latest 5 transactions for a specific user.
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   */
  async getLatestTransactionsForUser(req, res) {
    try {
      const { accountNumber } = req.params;
      const transactions = await TransactionService.getLatestTransactionsForUser(accountNumber);
      res.status(200).json(transactions);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get the latest 5 transactions across all users.
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   */
  async getLatestTransactions(req, res) {
    try {
      const transactions = await TransactionService.getLatestTransactions();
      res.status(200).json(transactions);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Update a transaction by ID.
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   */
  async updateTransaction(req, res) {
    try {
      const { id } = req.params;
      const update = req.body;
      const updatedTransaction = await TransactionService.updateTransaction(id, update);
      if (!updatedTransaction) {
        return res.status(404).json({ error: 'Transaction not found' });
      }
      res.status(200).json(updatedTransaction);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  /**
   * Update the status of a transaction by ID.
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   */
  async updateTransactionStatus(req, res) {
    try {
      const { id } = req.params;
      const { status } = req.body;
      const updatedTransaction = await TransactionService.updateTransactionStatus(id, status);
      if (!updatedTransaction) {
        return res.status(404).json({ error: 'Transaction not found' });
      }
      res.status(200).json(updatedTransaction);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  /**
   * Delete a transaction by ID.
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   */
  async deleteTransaction(req, res) {
    try {
      const { id } = req.params;
      const deletedTransaction = await TransactionService.deleteTransaction(id);
      if (!deletedTransaction) {
        return res.status(404).json({ error: 'Transaction not found' });
      }
      res.status(200).json({ message: 'Transaction deleted successfully', transaction: deletedTransaction });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get all transactions.
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   */
  async getAllTransactions(req, res) {
    try {
      const transactions = await Transaction.getAllTransactions();
      res.status(200).json(transactions);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  /**
   * Get transactions by account number.
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   */
  async getTransactionsByAccountNumber(req, res) {
    try {
      const { accountNumber } = req.params;
      const transactions = await TransactionService.getTransactionsByAccountNumber(accountNumber);
      res.status(200).json(transactions);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  /**
   * Get transactions with pending status.
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   */
  async getPendingTransactions(req, res) {
    try {
      const transactions = await TransactionService.getPendingTransactions();
      res.status(200).json(transactions);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
}

module.exports = new TransactionController();
