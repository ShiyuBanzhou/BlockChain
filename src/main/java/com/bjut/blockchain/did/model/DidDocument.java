package com.bjut.blockchain.did.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
// import java.security.PublicKey; // 此处不直接使用，但概念上相关
import java.util.Collections;
import java.util.List;
// import java.util.Map; // 此处不直接使用
import java.util.Objects;

/**
 * 简化的DID文档表示。
 * 包含DID、公钥等信息。
 * 参考 W3C DID Core 规范的简化版本。
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DidDocument implements Serializable {
    private static final long serialVersionUID = 1L;

    @JsonProperty("@context")
    private final List<String> context = Collections.singletonList("https://www.w3.org/ns/did/v1"); // JSON-LD 上下文

    @JsonProperty("id")
    private final String id; // DID 字符串

    @JsonProperty("verificationMethod")
    private List<VerificationMethod> verificationMethod; // 验证方法列表，例如包含公钥

    // 可以添加 authentication, assertionMethod, keyAgreement 等字段
    // @JsonProperty("authentication") // 认证方法，指向 verificationMethod 中的 id
    // private List<String> authentication;

    public DidDocument(String didString, List<VerificationMethod> verificationMethod) {
        this.id = didString;
        this.verificationMethod = verificationMethod;
    }

    public List<String> getContext() {
        return context;
    }

    public String getId() {
        return id;
    }

    public List<VerificationMethod> getVerificationMethod() {
        return verificationMethod;
    }

    public void setVerificationMethod(List<VerificationMethod> verificationMethod) {
        this.verificationMethod = verificationMethod;
    }

    // 内部类：验证方法
    public static class VerificationMethod implements Serializable {
        private static final long serialVersionUID = 1L;

        @JsonProperty("id")
        private String id; // 验证方法ID，例如 did#keys-1
        @JsonProperty("type")
        private String type; // 验证方法类型，例如 "Ed25519VerificationKey2018" 或 "EcdsaSecp256k1VerificationKey2019"
        @JsonProperty("controller")
        private String controller; // DID拥有者 (通常是DID本身)
        @JsonProperty("publicKeyBase58") // 或者 publicKeyJwk, publicKeyHex 等。此示例中存储Base64编码的公钥。
        private String publicKeyEncoded; // 公钥的编码字符串 (例如 Base64)

        public VerificationMethod() {}

        public VerificationMethod(String id, String type, String controller, String publicKeyEncoded) {
            this.id = id;
            this.type = type;
            this.controller = controller;
            this.publicKeyEncoded = publicKeyEncoded;
        }

        // Getters and Setters
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getController() { return controller; }
        public void setController(String controller) { this.controller = controller; }
        public String getPublicKeyEncoded() { return publicKeyEncoded; } // 修复：为了清晰，从 publicKeyBase58 重命名为 publicKeyEncoded
        public void setPublicKeyEncoded(String publicKeyEncoded) { this.publicKeyEncoded = publicKeyEncoded; }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            VerificationMethod that = (VerificationMethod) o;
            return Objects.equals(id, that.id) && Objects.equals(type, that.type) && Objects.equals(controller, that.controller) && Objects.equals(publicKeyEncoded, that.publicKeyEncoded);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, type, controller, publicKeyEncoded);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DidDocument that = (DidDocument) o;
        return Objects.equals(id, that.id) && Objects.equals(verificationMethod, that.verificationMethod);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, verificationMethod);
    }
}