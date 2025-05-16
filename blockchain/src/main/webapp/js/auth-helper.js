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
            // 防止循环重定向
            const currentUrl = window.location.href;
            // 检查是否在登录页面
            if (currentUrl.includes('login.html')) {
                return Promise.reject(new Error('未认证'));
            }
            
            // 检查重定向计数
            const redirectCount = parseInt(localStorage.getItem('redirect_count') || '0');
            if (redirectCount > 5) {
                // 重置计数
                localStorage.removeItem('redirect_count');
                localStorage.removeItem('blockchain_auth_status');
                // 强制重定向到登录页面并阻止新的重定向
                window.location.href = 'login.html?no_redirect=true';
                return Promise.reject(new Error('检测到循环重定向，已重置认证状态'));
            }
            
            // 增加重定向计数
            localStorage.setItem('redirect_count', (redirectCount + 1).toString());
            
            // 正常重定向到登录页面
            window.location.href = 'login.html?redirect=' + encodeURIComponent(window.location.href);
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
                localStorage.removeItem('redirect_count');
                alert('您的登录已过期，请重新登录');
                window.location.href = 'login.html?no_redirect=true';
                return Promise.reject(new Error('认证已过期'));
            }
            
            return response;
        } catch (error) {
            console.error('API请求失败:', error);
            return Promise.reject(error);
        }
    }
    
    /**
     * 验证服务器端认证状态
     * @returns {Promise<boolean>} 认证状态是否有效
     */
    static async verifyAuthStatus() {
        if (!this.isAuthenticated()) {
            return false;
        }
        
        try {
            const response = await fetch('/api/did/auth/session-status', {
                method: 'GET', 
                headers: {
                    'X-Auth-Token': this.getAuthToken(),
                    'X-Auth-Session': this.getSessionId(),
                    'X-Auth-DID': this.getCurrentDid() || ''
                }
            });
            
            if (response.ok) {
                const result = await response.json();
                if (result.isAuthenticated) {
                    // 重置重定向计数
                    localStorage.setItem('redirect_count', '0');
                    return true;
                }
            }
            
            // 认证失效，清除本地状态
            this.logout(false); // 不自动重定向
            return false;
        } catch (error) {
            console.error('验证认证状态失败:', error);
            return this.isAuthenticated(); // 网络错误时，保持当前状态
        }
    }
    
    /**
     * 注销当前用户
     * @param {boolean} redirect - 是否重定向到登录页面
     */
    static logout(redirect = true) {
        localStorage.removeItem('blockchain_auth_status');
        localStorage.removeItem('blockchain_auth_token');
        localStorage.removeItem('blockchain_auth_did');
        localStorage.removeItem('blockchain_auth_type');
        localStorage.removeItem('blockchain_auth_session');
        localStorage.removeItem('redirect_count');
        
        if (redirect) {
            window.location.href = 'login.html?no_redirect=true';
        }
    }
}

// 如果页面已加载，检查认证状态
document.addEventListener('DOMContentLoaded', () => {
    // 如果当前不是登录页面且未认证，则重定向到登录页面
    if (!window.location.pathname.includes('login.html') && !AuthHelper.isAuthenticated()) {
        // 检查重定向计数，防止循环重定向
        const redirectCount = parseInt(localStorage.getItem('redirect_count') || '0');
        if (redirectCount > 5) {
            // 重置认证状态和重定向计数
            localStorage.removeItem('blockchain_auth_status');
            localStorage.removeItem('redirect_count');
            window.location.href = 'login.html?no_redirect=true';
        } else {
            // 增加重定向计数
            localStorage.setItem('redirect_count', (redirectCount + 1).toString());
            window.location.href = 'login.html?redirect=' + encodeURIComponent(window.location.href);
        }
    } else if (AuthHelper.isAuthenticated()) {
        // 如果已认证，验证服务器端认证状态
        AuthHelper.verifyAuthStatus().then(isValid => {
            if (!isValid && !window.location.pathname.includes('login.html')) {
                window.location.href = 'login.html?no_redirect=true';
            }
        });
    }
}); 