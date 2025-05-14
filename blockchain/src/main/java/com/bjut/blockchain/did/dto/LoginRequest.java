package com.bjut.blockchain.did.dto; // 您可以根据项目结构调整包名

/**
 * 登录请求的数据传输对象
 */
public class LoginRequest {
    private String did; // DID 或用户名
    private String password; // 密码或密钥

    // Getter 和 Setter 方法
    public String getDid() {
        return did;
    }

    public void setDid(String did) {
        this.did = did;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
