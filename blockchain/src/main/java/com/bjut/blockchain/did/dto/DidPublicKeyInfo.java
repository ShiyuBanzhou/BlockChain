package com.bjut.blockchain.did.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 用于封装新公钥详细信息的数据传输对象。
 * 在DID文档更新（例如添加新的验证方法）时使用。
 */
@Getter
@Setter
@NoArgsConstructor
public class DidPublicKeyInfo {

    /**
     * 新验证方法的ID片段。
     * 例如，如果DID是 "did:example:123"，此片段可能是 "keys-2"。
     * 服务器通常会将DID前缀与此片段组合成完整的密钥ID，如 "did:example:123#keys-2"。
     * 客户端必须确保此片段在该DID的上下文中是唯一的（相对于其他验证方法ID的片段）。
     */
    private String idFragment;

    /**
     * 新验证方法的类型。
     * 例如："RsaVerificationKey2018", "EcdsaSecp256k1VerificationKey2019", "JsonWebKey2020" 等。
     * 这应与提供的publicKeyBase64的实际类型相匹配。
     */
    private String type;

    /**
     * 新公钥的Base64编码字符串（例如，SPKI格式）。
     */
    private String publicKeyBase64;

    /**
     * （可选）新验证方法的控制者。
     * 如果未提供或为空，通常默认为该DID文档的ID本身。
     * 可以是单个DID字符串，或DID字符串的列表（如果规范允许）。
     */
    private String controller; // 为了简单，这里假设是单个字符串
}
