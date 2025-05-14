package com.bjut.blockchain.did.model;

import com.bjut.blockchain.web.util.CommonUtil; // 引入 CommonUtil
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects; // 引入 Objects 用于 equals 和 hashCode

/**
 * 表示 DID 文档的模型类。
 * 包含有关 DID 主体的信息，例如公钥、认证方法和服务端点。
 * 基于 W3C DID Core 规范: https://www.w3.org/TR/did-core/
 */
public class DidDocument {

    // DID 主体，即该文档描述的 DID
    @Getter
    @Setter
    private String id;

    // 验证方法列表（例如，公钥）
    // 注意：为了方便修改，这里移除了final并添加了setter，或者确保在构造/使用时能正确填充
    @Getter
    @Setter
    private List<VerificationMethod> verificationMethod = new ArrayList<>();

    // 用于认证的验证方法ID列表
    @Getter
    @Setter
    private List<String> authentication = new ArrayList<>();

    // (可选) 服务端点列表
    @Getter
    @Setter
    private List<ServiceEndpoint> service; // 可能为 null，如果不需要

    /**
     * 计算此 DID 文档的 SHA-256 哈希值。
     * 先将文档序列化为 JSON 字符串，然后计算哈希。
     * @return 文档的 SHA-256 哈希值，如果序列化或计算出错则返回 null。
     */
    public String calculateDocumentHash() {
        try {
            // 注意：为确保哈希一致性，如果 CommonUtil.getJson 不保证字段顺序，需要配置或使用其他库。
            String jsonRepresentation = CommonUtil.getJson(this);
            return CommonUtil.calculateHash(jsonRepresentation);
        } catch (Exception e) {
            System.err.println("计算 DID 文档 " + (this.id != null ? this.id : "[ID未知]") + " 的哈希时出错: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    // --- equals, hashCode, toString (推荐实现) ---
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DidDocument that = (DidDocument) o;
        return Objects.equals(id, that.id); // 主要基于 ID 判断相等性
    }

    @Override
    public int hashCode() {
        return Objects.hash(id); // 主要基于 ID 计算哈希码
    }

    @Override
    public String toString() {
        // 可以使用 CommonUtil.getJson(this) 来获取更详细的字符串表示
        try {
            return CommonUtil.getJson(this);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            return "DidDocument{" +
                    "id='" + id + '\'' +
                    ", verificationMethodCount=" + (verificationMethod != null ? verificationMethod.size() : 0) +
                    ", authenticationCount=" + (authentication != null ? authentication.size() : 0) +
                    '}';
        }
    }


    // --- 嵌套内部类 ---

    /**
     * 表示 DID 文档中的验证方法（例如公钥）。
     */
    public static class VerificationMethod {
        @Getter @Setter private String id; // 验证方法 ID (例如 "did:example:123#keys-1")
        @Getter @Setter private String type; // 验证方法类型 (例如 "RsaVerificationKey2018")
        @Getter @Setter private String controller; // 控制此方法的 DID
        @Getter @Setter private String publicKeyJwk; // JWK 格式的公钥 (可选)
        @Getter @Setter private String publicKeyMultibase; // Multibase 格式的公钥 (可选)
        @Getter @Setter private String publicKeyBase58; // Base58 格式的公钥 (可选, 保留以备他用)
        @Getter @Setter private String publicKeyBase64; // Base64 格式的公钥 (适用于 RSA/EC X.509)
        @Getter @Setter private String x509CertificateFingerprint; // X.509证书指纹 (可选)


        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            VerificationMethod that = (VerificationMethod) o;
            return Objects.equals(id, that.id); // 基于 ID 判断
        }

        @Override
        public int hashCode() {
            return Objects.hash(id); // 基于 ID 计算
        }

        @Override
        public String toString() {
            return "VerificationMethod{" +
                    "id='" + id + '\'' +
                    ", type='" + type + '\'' +
                    '}';
        }
    }

    /**
     * 表示 DID 文档中的服务端点。
     */
    public static class ServiceEndpoint {
        @Getter @Setter private String id; // 服务端点 ID (例如 "did:example:123#service-1")
        @Getter @Setter private String type; // 服务类型 (例如 "DIDCommMessaging")
        @Getter @Setter private String serviceEndpoint; // 服务的 URL 或 URI


        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ServiceEndpoint that = (ServiceEndpoint) o;
            return Objects.equals(id, that.id); // 基于 ID 判断
        }

        @Override
        public int hashCode() {
            return Objects.hash(id); // 基于 ID 计算
        }

        @Override
        public String toString() {
            return "ServiceEndpoint{" +
                    "id='" + id + '\'' +
                    ", type='" + type + '\'' +
                    ", serviceEndpoint='" + serviceEndpoint + '\'' +
                    '}';
        }
    }
}