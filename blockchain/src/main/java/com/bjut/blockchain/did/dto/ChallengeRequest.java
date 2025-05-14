package com.bjut.blockchain.did.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 用于请求挑战的数据传输对象。
 * 通常在登录或需要授权的操作（如DID文档更新）的第一步使用。
 */
@Getter
@Setter
@NoArgsConstructor // Lombok: 生成无参构造函数
public class ChallengeRequest {

    /**
     * 用户或实体的DID (Decentralized Identifier)。
     * 服务器将为这个DID生成一个挑战。
     */
    private String did;

    // 如果是用于特定操作（如更新），可能还需要其他字段，
    // 例如用于授权该操作的现有密钥ID。
    // 对于登录，通常只需要did。
    // 对于我们实现的 /api/did/update/challenge，它接收的是 Map<String, String>，
    // 但如果将其DTO化，它可能包含 did 和 authorizingKeyId。
    // 为保持此DTO通用，仅保留did。Controller中可以根据需要调整。
}
