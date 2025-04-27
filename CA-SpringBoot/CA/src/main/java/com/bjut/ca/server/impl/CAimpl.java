package com.bjut.ca.server.impl;

import com.alibaba.fastjson.JSON;
import com.bjut.ca.Util.CertificateValidator;
import com.bjut.ca.Util.PublicKeyUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import static com.bjut.ca.Util.CertificateValidator.validateCertificate;

@Service
public class CAimpl {

    private KeyPair caKeyPair;
    private X509Certificate caCertificate;

    public CAimpl() throws NoSuchAlgorithmException, CertificateException, OperatorCreationException {
        Security.addProvider(new BouncyCastleProvider());
        caKeyPair = generateKeyPair();
        caCertificate = generateCACertificate(caKeyPair);
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private X509Certificate generateCACertificate(KeyPair keyPair) throws OperatorCreationException, CertificateException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        X500Name issuer = new X500Name("CN=CA, OU=CA, O=CA, L=CA, ST=CA, C=CA");
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Calendar calendar = Calendar.getInstance();
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                startDate,
                endDate,
                issuer,
                publicKey
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
    }

    public X509Certificate issueCertificate(PublicKey subjectPublicKey, String subjectDN) throws OperatorCreationException, CertificateException {
        PrivateKey caPrivateKey = caKeyPair.getPrivate();

        X500Name issuer = new X500Name(caCertificate.getSubjectX500Principal().getName());
        X500Name subject = new X500Name(subjectDN);
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Calendar calendar = Calendar.getInstance();
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                startDate,
                endDate,
                subject,
                subjectPublicKey
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
    }

    public X509Certificate getCA(String userPublicKey, String userDN) throws Exception {
        // 解析公钥
        PublicKey parsedPublicKey = PublicKeyUtil.stringToPublicKey(userPublicKey, "RSA");
        return issueCertificate(parsedPublicKey, userDN);

    }


    public X509Certificate getCACertificate() {
        return caCertificate;
    }

    public static void main(String[] args) {
        try {
            CAimpl ca = new CAimpl();

            // 获取根证书
            X509Certificate rootCertificate = ca.getCACertificate();
            System.out.println("根证书信息:");
            System.out.println("主题: " + rootCertificate.getSubjectDN());
            System.out.println("颁发者: " + rootCertificate.getIssuerDN());
            System.out.println("有效期开始: " + rootCertificate.getNotBefore());
            System.out.println("有效期结束: " + rootCertificate.getNotAfter());

            KeyPair userKeyPair = ca.generateKeyPair();
            PublicKey userPublicKey = userKeyPair.getPublic();
            String userDN = "CN=User, OU=User, O=User, L=User, ST=User, C=User";

            X509Certificate userCertificate = ca.issueCertificate(userPublicKey, userDN);

            System.out.println("用户证书信息:");
            System.out.println("主题: " + userCertificate.getSubjectDN());
            System.out.println("颁发者: " + userCertificate.getIssuerDN());
            System.out.println("有效期开始: " + userCertificate.getNotBefore());
            System.out.println("有效期结束: " + userCertificate.getNotAfter());
            // 验证 A 的证书
            boolean isValid = CertificateValidator.validateCertificate(userCertificate, rootCertificate);
            System.out.println("A 的证书是否合法: " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}