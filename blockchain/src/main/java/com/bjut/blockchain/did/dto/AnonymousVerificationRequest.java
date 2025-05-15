package com.bjut.blockchain.did.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 用于匿名认证时，客户端提交临时公钥和签名以供验证的DTO。
 * Data Transfer Object for anonymous authentication verification.
 * It carries the challenge, the temporary public key, and the signature from the client.
 */
@Getter
@Setter
@NoArgsConstructor
public class AnonymousVerificationRequest {

    /**
     * 服务器先前下发的挑战字符串。
     * The challenge string previously issued by the server.
     */
    private String challenge;

    /**
     * 客户端生成的临时公钥 (Base64编码)。
     * The client-generated temporary public key, Base64 encoded.
     */
    private String temporaryPublicKeyBase64;

    /**
     * 客户端使用临时私钥对挑战进行的签名 (Base64编码)。
     * The signature of the challenge, created using the temporary private key, Base64 encoded.
     */
    private String signatureBase64;

}
