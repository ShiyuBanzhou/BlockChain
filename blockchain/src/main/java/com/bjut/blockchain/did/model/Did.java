package com.bjut.blockchain.did.model;

/**
 * 表示一个去中心化标识符 (DID)。
 * 包含 DID 字符串本身。
 */
public class Did {

    private final String didString; // DID 字符串，例如 "did:example:123456789abcdefghi"

    /**
     * 构造函数，使用给定的字符串创建一个 DID 对象。
     * @param didString DID 字符串。
     */
    public Did(String didString) {
        // 可以在这里添加对 didString 格式的验证逻辑
        if (didString == null || !didString.startsWith("did:")) {
            throw new IllegalArgumentException("Invalid DID format: " + didString);
        }
        this.didString = didString;
    }

    /**
     * 获取 DID 字符串。
     * @return DID 字符串。
     */
    public String getDidString() {
        return didString;
    }

    @Override
    public String toString() {
        return didString;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Did did = (Did) o;
        return didString.equals(did.didString);
    }

    @Override
    public int hashCode() {
        return didString.hashCode();
    }
}
