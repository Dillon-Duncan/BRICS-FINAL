const Transaction = require('../models/transaction'); // Correct capitalization for the model

class TransactionService {
  /**
   * Create a new transaction.
   * @param {Object} transaction - The transaction details to create.
   * @returns {Object} - The newly created transaction document.
   */
  async createTransaction(transaction) {
    try {
      console.log('Transaction data:', transaction); // Log the transaction data
      // Ensures schema validation is applied.
      return await Transaction.create(transaction);
    } catch (error) {
      if (error.name === 'ValidationError') {
        const errors = Object.values(error.errors).map(err => err.message);
        throw new Error(`Validation Error: ${errors.join(', ')}`);
      }
      throw new Error(`Error creating transaction: ${error.message}`);
    }
  }

  /**
   * Retrieve all transactions.
   * @returns {Array} - A list of all transactions.
   */
  async getTransactions() {
    try {
      return await Transaction.find();
    } catch (error) {
      throw new Error(`Error retrieving transactions: ${error.message}`);
    }
  }

  /**
   * Retrieve a single transaction by its ID.
   * @param {String} id - The transaction ID to retrieve.
   * @returns {Object|null} - The found transaction or null if not found.
   */
  async getTransactionById(id) {
    try {
      const transaction = await Transaction.findById(id);
      if (!transaction) {
        throw new Error(`Transaction not found with ID: ${id}`);
      }
      return transaction;
    } catch (error) {
      throw new Error(`Error retrieving transaction by ID: ${error.message}`);
    }
  }

  /**
   * Retrieve the 5 latest transactions for a specific user.
   * @param {String} accountNumber - The account number of the user.
   * @returns {Array} - The latest 5 transactions for the user.
   */
  async getLatestTransactionsForUser(accountNumber) {
    try {
      const transactions = await Transaction.find({
        $or: [{ fromAccount: accountNumber }, { toAccount: accountNumber }],
      })
        .sort({ createdAt: -1 }) // Sort by creation date in descending order.
        .limit(5); // Limit to the latest 5 transactions.

      if (transactions.length === 0) {
        throw new Error(`No transactions found for account number: ${accountNumber}`);
      }

      return transactions;
    } catch (error) {
      throw new Error(`Error retrieving latest transactions for user: ${error.message}`);
    }
  }

  /**
   * Retrieve the 5 latest transactions across all users.
   * @returns {Array} - The latest 5 transactions across all users.
   */
  async getLatestTransactions() {
    try {
      const transactions = await Transaction.find()
        .sort({ createdAt: -1 }) // Sort by creation date in descending order.
        .limit(5); // Limit to the latest 5 transactions.

      return transactions;
    } catch (error) {
      throw new Error(`Error retrieving latest transactions: ${error.message}`);
    }
  }

  /**
   * Retrieve all transactions.
   * @returns {Array} - A list of all transactions.
   */
  async getAllTransactions() {
    try {
      return await Transaction.find();
    } catch (error) {
      throw new Error(`Error retrieving all transactions: ${error.message}`);
    }
  }

  /**
   * Retrieve transactions by account number.
   * @param {String} accountNumber - The account number to find transactions.
   * @returns {Array} - A list of transactions for the user.
   */
  async getTransactionsByAccountNumber(accountNumber) {
    try {
      const transactions = await Transaction.find({
        $or: [{ fromAccount: accountNumber }, { toAccount: accountNumber }],
      });
      return transactions;
    } catch (error) {
      throw new Error(`Error retrieving transactions: ${error.message}`);
    }
  }

  /**
   * Retrieve transactions with pending status.
   * @returns {Array} - A list of transactions with pending status.
   */
  async getPendingTransactions() {
    try {
      const transactions = await Transaction.find({ status: 'Pending' });
      return transactions;
    } catch (error) {
      throw new Error(`Error retrieving pending transactions: ${error.message}`);
    }
  }

  /**
   * Update a transaction by its ID.
   * @param {String} id - The transaction ID to update.
   * @param {Object} update - The updates to apply to the transaction.
   * @returns {Object|null} - The updated transaction or null if not found.
   */
  async updateTransaction(id, update) {
    try {
      const updatedTransaction = await Transaction.findByIdAndUpdate(id, update, {
        new: true,
        runValidators: true,
      });

      if (!updatedTransaction) {
        throw new Error(`Transaction not found with ID: ${id}`);
      }

      return updatedTransaction;
    } catch (error) {
      if (error.name === 'ValidationError') {
        const errors = Object.values(error.errors).map(err => err.message);
        throw new Error(`Validation Error: ${errors.join(', ')}`);
      }
      throw new Error(`Error updating transaction: ${error.message}`);
    }
  }

  /**
   * Update the status of a transaction.
   * @param {String} id - The transaction ID to update.
   * @param {String} status - The new status to set.
   * @returns {Object|null} - The updated transaction or null if not found.
   */
  async updateTransactionStatus(id, status) {
    try {
      const updatedTransaction = await Transaction.findByIdAndUpdate(
        id,
        { status },
        { new: true, runValidators: true }
      );

      if (!updatedTransaction) {
        throw new Error(`Transaction not found with ID: ${id}`);
      }

      return updatedTransaction;
    } catch (error) {
      throw new Error(`Error updating transaction status: ${error.message}`);
    }
  }

  /**
   * Delete a transaction by its ID.
   * @param {String} id - The transaction ID to delete.
   * @returns {Object|null} - The deleted transaction or null if not found.
   */
  async deleteTransaction(id) {
    try {
      const deletedTransaction = await Transaction.findByIdAndDelete(id);
      if (!deletedTransaction) {
        throw new Error(`Transaction not found with ID: ${id}`);
      }
      return deletedTransaction;
    } catch (error) {
      throw new Error(`Error deleting transaction: ${error.message}`);
    }
  }
}

module.exports = new TransactionService();
