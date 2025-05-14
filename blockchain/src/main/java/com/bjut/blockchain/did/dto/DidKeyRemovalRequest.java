package com.bjut.blockchain.did.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 用于提交DID文档中移除验证方法（密钥）请求的数据传输对象。
 */
@Getter
@Setter
@NoArgsConstructor
public class DidKeyRemovalRequest {

    /**
     * 要更新的目标DID字符串。
     */
    private String did;

    /**
     * 要从DID文档中移除的验证方法（密钥）的完整ID。
     * 例如："did:example:123#keys-2"
     */
    private String keyIdToRemove;

    /**
     * 用于授权此移除操作的、已存在于目标DID文档中的验证方法（密钥）的完整ID。
     * 例如："did:example:123#keys-1"
     * 客户端需要使用与此密钥ID对应的私钥对更新负载进行签名。
     */
    private String authorizingKeyId;

    /**
     * 服务器先前为此次移除操作提供的挑战字符串。
     */
    private String challenge;

    /**
     * 客户端对包含移除意图、挑战等内容的规范化负载的签名（Base64编码）。
     * 此签名是使用与 authorizingKeyId 对应的私钥生成的。
     */
    private String signatureBase64;
}