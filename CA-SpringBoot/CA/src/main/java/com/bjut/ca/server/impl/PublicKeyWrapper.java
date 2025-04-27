package com.bjut.ca.server.impl;

import com.alibaba.fastjson.JSON;
import com.bjut.ca.Util.PublicKeyUtil;

import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class PublicKeyWrapper {
    private String publicKeyBase64;

    public PublicKeyWrapper(PublicKey publicKey) throws Exception {
        byte[] publicKeyBytes = publicKey.getEncoded();
        this.publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    public String getPublicKeyBase64() {
        return publicKeyBase64;
    }

    public void setPublicKeyBase64(String publicKeyBase64) {
        this.publicKeyBase64 = publicKeyBase64;
    }

    public PublicKey getPublicKey() throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(keySpec);
    }


    public static void main(String[] args) {
        try {
            // 生成密钥对
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            System.out.println(PublicKeyUtil.publicKeyToString(publicKey));
            CAimpl ca = new CAimpl();
            X509Certificate certificate = ca.getCA(PublicKeyUtil.publicKeyToString(publicKey), "CN=User, OU=User, O=User, L=User, ST=User, C=User");
            System.out.println(certificate);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}

