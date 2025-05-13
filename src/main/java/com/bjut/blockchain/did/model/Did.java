package com.bjut.blockchain.did.model;

import java.io.Serializable;
import java.util.Objects;

/**
 * 简化的DID表示。
 * 格式通常是 did:method:specific-identifier
 * 例如: did:example:123456789abcdefghi
 */
public class Did implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String method = "example"; // DID方法，初期简化为 "example"
    private final String specificIdentifier; // 特定标识符

    public Did(String specificIdentifier) {
        if (specificIdentifier == null || specificIdentifier.trim().isEmpty()) {
            throw new IllegalArgumentException("Specific identifier 不能为空"); // 特定标识符不能为空
        }
        this.specificIdentifier = specificIdentifier;
    }

    public String getMethod() {
        return method;
    }

    public String getSpecificIdentifier() {
        return specificIdentifier;
    }

    /**
     * 返回完整的DID字符串。
     * @return 例如 "did:example:123456789abcdefghi"
     */
    public String getFullDid() { // 修复：修正了方法名
        return "did:" + method + ":" + specificIdentifier;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Did did = (Did) o;
        return method.equals(did.method) && specificIdentifier.equals(did.specificIdentifier);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, specificIdentifier);
    }

    @Override
    public String toString() {
        return getFullDid();
    }
}