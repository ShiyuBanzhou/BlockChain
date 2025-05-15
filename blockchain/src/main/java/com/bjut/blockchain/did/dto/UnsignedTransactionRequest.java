package com.bjut.blockchain.did.dto;

/**
 * 用于接收客户端发送的、尚未签名的交易数据的DTO。
 * 主要用于调试和演示目的的签名辅助接口。
 */
public class UnsignedTransactionRequest {
    private String dataToStore; // 用户希望存储到区块链上的数据
    private String userDid;     // 发起交易用户的DID
    private String privateKeyHex; // 用户提供的私钥（十六进制字符串格式），仅用于调试签名

    // Getters and Setters

    public String getDataToStore() {
        return dataToStore;
    }

    public void setDataToStore(String dataToStore) {
        this.dataToStore = dataToStore;
    }

    public String getUserDid() {
        return userDid;
    }

    public void setUserDid(String userDid) {
        this.userDid = userDid;
    }

    public String getPrivateKeyHex() {
        return privateKeyHex;
    }

    public void setPrivateKeyHex(String privateKeyHex) {
        this.privateKeyHex = privateKeyHex;
    }

    @Override
    public String toString() {
        // 注意：实际生产中不应轻易打印私钥内容
        return "UnsignedTransactionRequest{" +
                "dataToStore='" + dataToStore + '\'' +
                ", userDid='" + userDid + '\'' +
                ", privateKeyHex='[PROTECTED]" + '\'' + // 避免直接暴露私钥
                '}';
    }
}
