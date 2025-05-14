package com.bjut.blockchain.did.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 用于创建新DID时，客户端向服务器提供信息的DTO。
 */
@Getter
@Setter
@NoArgsConstructor
public class CreateDidRequest {

    /**
     * 客户端生成的公钥，通常是Base64编码的SPKI (SubjectPublicKeyInfo) 格式。
     * 服务器将使用此公钥在新的DID文档中创建验证方法。
     */
    private String publicKeyBase64;

    // 根据需要，还可以添加其他与DID创建相关的初始信息，
    // 例如期望的DID方法（如果服务器支持多种）、初始服务断点等。
}
