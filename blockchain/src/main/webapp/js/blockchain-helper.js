/**
 * 区块链助手类 - 处理区块链相关的API请求
 */
class BlockchainHelper {
    constructor() {
        this.BASE_URL = 'http://localhost:8080/api';
    }
    
    /**
     * 创建创世区块
     * @returns {Promise<Object>} 响应对象
     */
    async createGenesisBlock() {
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/blocks/genesis`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            return await response.json();
        } catch (error) {
            console.error('创建创世区块失败:', error);
            throw error;
        }
    }
    
    /**
     * 获取区块链
     * @returns {Promise<Object>} 区块链数据
     */
    async getBlockchain() {
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/blocks/chain`, {
                method: 'GET'
            });
            return await response.json();
        } catch (error) {
            console.error('获取区块链失败:', error);
            throw error;
        }
    }
    
    /**
     * 挖掘新区块
     * @returns {Promise<Object>} 新区块数据
     */
    async mineBlock() {
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/blocks/mine`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            return await response.json();
        } catch (error) {
            console.error('挖掘区块失败:', error);
            throw error;
        }
    }
    
    /**
     * 获取已打包的交易
     * @returns {Promise<Object>} 交易数据
     */
    async getPackedTransactions() {
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/blocks/transactions/packed`, {
                method: 'GET'
            });
            return await response.json();
        } catch (error) {
            console.error('获取已打包交易失败:', error);
            throw error;
        }
    }
    
    /**
     * 获取待处理的交易
     * @returns {Promise<Object>} 交易数据
     */
    async getPendingTransactions() {
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/blocks/transactions/pending`, {
                method: 'GET'
            });
            return await response.json();
        } catch (error) {
            console.error('获取待处理交易失败:', error);
            throw error;
        }
    }
    
    /**
     * 创建新交易
     * @param {Object} transaction 交易数据
     * @returns {Promise<Object>} 响应对象
     */
    async createTransaction(transaction) {
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/blocks/transactions/new`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(transaction)
            });
            return await response.json();
        } catch (error) {
            console.error('创建交易失败:', error);
            throw error;
        }
    }
    
    /**
     * 检查用户认证状态
     * @returns {Promise<Object>} 认证状态信息
     */
    async checkAuthStatus() {
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/did/auth/session-status`, {
                method: 'GET'
            });
            return await response.json();
        } catch (error) {
            console.error('检查认证状态失败:', error);
            throw error;
        }
    }
}

// 创建全局实例
const blockchainAPI = new BlockchainHelper(); 