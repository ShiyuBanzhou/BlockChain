/**
 * 选举相关的辅助类
 * 提供与区块链投票系统中选举相关的API调用方法
 */
class ElectionHelper {
    constructor() {
        this.BASE_URL = '/api';
    }
    
    /**
     * 获取进行中的选举
     * @returns {Promise<Array>} 选举数据数组
     */
    async getActiveElections() {
        // 尝试从缓存获取数据
        const cachedData = getCachedData('active_elections');
        if (cachedData) {
            return cachedData;
        }
        
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/elections/active`, {
                method: 'GET'
            });
            const data = await response.json();
            
            // 缓存数据
            cacheData('active_elections', data, 5); // 缓存5分钟
            
            return data;
        } catch (error) {
            console.error('获取进行中的选举失败:', error);
            throw error;
        }
    }
    
    /**
     * 获取所有选举
     * @returns {Promise<Array>} 选举数据数组
     */
    async getAllElections() {
        // 尝试从缓存获取数据
        const cachedData = getCachedData('all_elections');
        if (cachedData) {
            return cachedData;
        }
        
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/elections`, {
                method: 'GET'
            });
            const data = await response.json();
            
            // 缓存数据
            cacheData('all_elections', data, 5); // 缓存5分钟
            
            return data;
        } catch (error) {
            console.error('获取所有选举失败:', error);
            throw error;
        }
    }
    
    /**
     * 获取选举详情
     * @param {string} electionId 选举ID
     * @returns {Promise<Object>} 选举详情
     */
    async getElectionById(electionId) {
        // 尝试从缓存获取数据
        const cachedData = getCachedData(`election_${electionId}`);
        if (cachedData) {
            return cachedData;
        }
        
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/elections/${electionId}`, {
                method: 'GET'
            });
            const data = await response.json();
            
            // 缓存数据
            cacheData(`election_${electionId}`, data, 5); // 缓存5分钟
            
            return data;
        } catch (error) {
            console.error(`获取选举(ID: ${electionId})详情失败:`, error);
            throw error;
        }
    }
    
    /**
     * 创建新选举
     * @param {Object} electionData 选举数据
     * @returns {Promise<Object>} 创建的选举数据
     */
    async createElection(electionData) {
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/elections`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(electionData)
            });
            return await response.json();
        } catch (error) {
            console.error('创建选举失败:', error);
            throw error;
        }
    }
    
    /**
     * 更新选举信息
     * @param {Object} electionData 选举数据
     * @returns {Promise<Object>} 更新后的选举数据
     */
    async updateElection(electionData) {
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/elections/${electionData.electionId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(electionData)
            });
            return await response.json();
        } catch (error) {
            console.error(`更新选举(ID: ${electionData.electionId})失败:`, error);
            throw error;
        }
    }
    
    /**
     * 删除选举
     * @param {string} electionId 选举ID
     * @returns {Promise<Object>} 响应数据
     */
    async deleteElection(electionId) {
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/elections/${electionId}`, {
                method: 'DELETE'
            });
            return await response.json();
        } catch (error) {
            console.error(`删除选举(ID: ${electionId})失败:`, error);
            throw error;
        }
    }
    
    /**
     * 获取选举的投票统计
     * @param {string} electionId 选举ID
     * @returns {Promise<Object>} 投票统计数据
     */
    async getVoteCountsByElection(electionId) {
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/votes/count/${electionId}`, {
                method: 'GET'
            });
            return await response.json();
        } catch (error) {
            console.error(`获取选举(ID: ${electionId})投票统计失败:`, error);
            throw error;
        }
    }
    
    /**
     * 获取选举的所有投票
     * @param {string} electionId 选举ID
     * @returns {Promise<Array>} 投票数据数组
     */
    async getVotesByElection(electionId) {
        try {
            const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/votes/election/${electionId}`, {
                method: 'GET'
            });
            return await response.json();
        } catch (error) {
            console.error(`获取选举(ID: ${electionId})的投票失败:`, error);
            throw error;
        }
    }
    
    /**
     * 提交投票
     * @param {Object} voteData 投票数据
     * @returns {Promise<Object>} 创建的投票数据
     */
    async castVote(voteData) {
        const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/votes`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(voteData)
        });
        
        if (!response.ok) {
            throw new Error('投票失败');
        }
        
        const result = await response.json();
        
        // 投票成功后，更新区块链状态
        try {
            await this.updateElectionBlockchainStatus(voteData.electionId);
            // 清除相关缓存，确保下次获取最新数据
            localStorage.removeItem(`election_${voteData.electionId}`);
            localStorage.removeItem('active_elections');
            localStorage.removeItem('all_elections');
        } catch (error) {
            console.warn('更新区块链状态失败，但投票已成功', error);
        }
        
        return result;
    }
    
    // 新增：更新选举区块链状态
    async updateElectionBlockchainStatus(electionId) {
        const response = await AuthHelper.fetchWithAuth(`${this.BASE_URL}/elections/${electionId}/blockchain-status`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ status: '已记录' })
        });
        
        if (!response.ok) {
            throw new Error('更新区块链状态失败');
        }
        
        return await response.json();
    }
}

// 添加缓存功能
function cacheData(key, data, expirationMinutes = 10) {
  const item = {
    data: data,
    timestamp: new Date().getTime(),
    expiration: expirationMinutes * 60 * 1000
  };
  localStorage.setItem(key, JSON.stringify(item));
}

function getCachedData(key) {
  const item = localStorage.getItem(key);
  if (!item) return null;
  
  const parsedItem = JSON.parse(item);
  const now = new Date().getTime();
  if (now - parsedItem.timestamp > parsedItem.expiration) {
    localStorage.removeItem(key);
    return null;
  }
  return parsedItem.data;
} 