/**
 * 认证助手类 - 处理区块链应用的认证和请求
 */
class AuthHelper {
    
    /**
     * 检查用户是否已认证
     * @returns {boolean} 是否已认证
     */
    static isAuthenticated() {
        return localStorage.getItem('blockchain_auth_status') === 'authenticated';
    }
    
    /**
     * 获取认证类型 (did 或 anonymous)
     * @returns {string} 认证类型
     */
    static getAuthType() {
        return localStorage.getItem('blockchain_auth_type') || 'did';
    }
    
    /**
     * 获取当前DID (如果存在)
     * @returns {string} 当前DID或null
     */
    static getCurrentDid() {
        return localStorage.getItem('blockchain_auth_did');
    }
    
    /**
     * 获取认证Token
     * @returns {string} 认证Token
     */
    static getAuthToken() {
        return localStorage.getItem('blockchain_auth_token');
    }
    
    /**
     * 获取会话ID
     * @returns {string} 会话ID
     */
    static getSessionId() {
        return localStorage.getItem('blockchain_auth_session') || '';
    }
    
    /**
     * 执行带有认证信息的API请求
     * @param {string} url - API URL
     * @param {Object} options - 请求选项
     * @returns {Promise<Object>} - 响应对象
     */
    static async fetchWithAuth(url, options = {}) {
        if (!this.isAuthenticated()) {
            window.location.href = 'login.html';
            return Promise.reject(new Error('未认证'));
        }
        
        // 设置默认选项
        options.headers = options.headers || {};
        
        // 添加认证头
        options.headers['X-Auth-Token'] = this.getAuthToken();
        options.headers['X-Auth-Session'] = this.getSessionId();
        options.headers['X-Auth-DID'] = this.getCurrentDid() || '';
        
        // 如果没有指定Content-Type，且是POST请求，则设置默认值
        if (!options.headers['Content-Type'] && options.method === 'POST') {
            options.headers['Content-Type'] = 'application/json';
        }
        
        try {
            const response = await fetch(url, options);
            
            // 处理未授权错误
            if (response.status === 401) {
                console.error('认证已过期或无效');
                localStorage.removeItem('blockchain_auth_status');
                alert('您的登录已过期，请重新登录');
                window.location.href = 'login.html';
                return Promise.reject(new Error('认证已过期'));
            }
            
            return response;
        } catch (error) {
            console.error('API请求失败:', error);
            return Promise.reject(error);
        }
    }
    
    /**
     * 注销当前用户
     */
    static logout() {
        localStorage.removeItem('blockchain_auth_status');
        localStorage.removeItem('blockchain_auth_token');
        localStorage.removeItem('blockchain_auth_did');
        localStorage.removeItem('blockchain_auth_type');
        localStorage.removeItem('blockchain_auth_session');
        
        window.location.href = 'login.html';
    }
}

// 如果页面已加载，检查认证状态
document.addEventListener('DOMContentLoaded', () => {
    // 如果当前不是登录页面且未认证，则重定向到登录页面
    if (!window.location.pathname.includes('login.html') && !AuthHelper.isAuthenticated()) {
        window.location.href = 'login.html';
    }
}); 