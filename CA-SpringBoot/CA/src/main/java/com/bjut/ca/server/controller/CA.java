package com.bjut.ca.server.controller;

import com.alibaba.fastjson.JSON;
import com.bjut.ca.Util.CertificateValidator;
import com.bjut.ca.Util.PublicKeyUtil;
import com.bjut.ca.Util.X509CertificateUtil;
import com.bjut.ca.server.impl.CAimpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.Parameter;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
public class CA {

    @Autowired
    CAimpl cAimpl;
    /**
     * 获取用户指定参数的CA证书
     *
     * @param userPublicKey 用户公钥，用于生成CA证书
     * @param userDN 用户DN（Distinguished Name），用于标识用户信息
     * @return 返回生成的CA证书的字符串表示
     * @throws Exception 如果生成CA证书过程中出现异常，则抛出此异常
     */
    @PostMapping("/ca")
    public String getCA(@Parameter(description="用户公钥") String userPublicKey
                        ,@Parameter(description="用户DN") String userDN) throws Exception {
        userPublicKey = userPublicKey.replace(" ", "+");
        X509Certificate ca = cAimpl.getCA(userPublicKey, userDN);
        System.out.println(X509CertificateUtil.certificateToString(ca));
        return X509CertificateUtil.certificateToString(ca);
    }

    /**
     * 获取根CA证书
     *
     * @return 返回根CA证书的字符串表示
     * @throws Exception 如果获取根CA证书过程中出现异常，则抛出此异常
     */
    @GetMapping("/root-ca")
    public String getRootCA() throws Exception {
        X509Certificate ca = cAimpl.getCACertificate();
        return X509CertificateUtil.certificateToString(ca);
    }


    //测试文件
    public static void main(String[] args) {
        try {
            CAimpl ca = new CAimpl();
            KeyPair userKeyPair = ca.generateKeyPair();
            PublicKey userPublicKey = userKeyPair.getPublic();
            String userDN = "CN=User, OU=User, O=00r, L=User, ST=User, C=User";

            X509Certificate userCertificate = ca.issueCertificate(userPublicKey, userDN);
            String a=X509CertificateUtil.certificateToString(userCertificate);
            X509Certificate c=X509CertificateUtil.stringToCertificate(a);

            System.out.println(X509CertificateUtil.stringToCertificate(a));

            X509Certificate certificate2 =ca.getCACertificate();
            String a1=X509CertificateUtil.certificateToString(certificate2);
            X509Certificate c2=X509CertificateUtil.stringToCertificate(a1);
            System.out.println(CertificateValidator.validateCertificate(c,c2));
            System.out.println(CertificateValidator.validateCertificate(userCertificate,certificate2));
            System.out.println(a);
            System.out.println(a1);
            System.out.println(CertificateValidator.validateCertificateByString(a,a1));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
