package com.bjut.blockchain.did.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 用于提交验证信息的数据传输对象。
 * 通常在挑战-响应流程的第二步，客户端提交其对挑战的签名时使用。
 */
@Getter
@Setter
@NoArgsConstructor
public class VerificationRequest {

    /**
     * 用户或实体的DID。
     */
    private String did;

    /**
     * 客户端声称已签名的原始挑战字符串。
     * 服务器会将其与会话中存储的挑战进行比较。
     */
    private String challenge;

    /**
     * 客户端对挑战（或特定负载）的签名，通常为Base64编码。
     */
    private String signatureBase64;

    /**
     * DID文档中用于生成此签名的验证方法（公钥）的完整ID。
     * 例如："did:example:12345#keys-1"
     */
    private String keyId;
}
