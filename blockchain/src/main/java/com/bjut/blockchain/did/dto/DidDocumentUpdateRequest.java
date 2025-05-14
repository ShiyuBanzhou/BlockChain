package com.bjut.blockchain.did.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 用于提交DID文档更新请求的数据传输对象。
 * 例如，用于添加新的验证方法（公钥）。
 */
@Getter
@Setter
@NoArgsConstructor
public class DidDocumentUpdateRequest {

    /**
     * 要更新的目标DID字符串。
     */
    private String did;

    /**
     * 包含要添加的新公钥（或其他验证方法）的详细信息。
     */
    private DidPublicKeyInfo newPublicKeyInfo;

    /**
     * 用于授权此更新操作的、已存在于目标DID文档中的验证方法（密钥）的完整ID。
     * 例如："did:example:123#keys-1"
     * 客户端需要使用与此密钥ID对应的私钥对更新负载进行签名。
     */
    private String authorizingKeyId;

    /**
     * 服务器先前为此次更新操作提供的挑战字符串。
     * 客户端在构造签名负载时需要包含此挑战。
     */
    private String challenge;

    /**
     * 客户端对包含新公钥信息、挑战等内容的规范化更新负载的签名（Base64编码）。
     * 此签名是使用与 authorizingKeyId 对应的私钥生成的。
     */
    private String signatureBase64;
}
