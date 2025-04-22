package com.simulation.blockchain.security;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.net.ssl.*;

public class SecurityUtils {
    public static SSLContext initSSLContext(
            String keyStorePath, String keyStorePwd,
            String trustStorePath, String trustStorePwd
    ) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keyStorePath)) {
            ks.load(fis, keyStorePwd.toCharArray());
        }
        KeyStore ts = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(trustStorePath)) {
            ts.load(fis, trustStorePwd.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, keyStorePwd.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    public static byte[] signData(String data, PrivateKey privKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privKey);
        sig.update(data.getBytes(StandardCharsets.UTF_8));
        return sig.sign();
    }

    public static boolean verifyData(
            String data, byte[] signature, PublicKey pubKey
    ) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);
        sig.update(data.getBytes(StandardCharsets.UTF_8));
        return sig.verify(signature);
    }

    public static X509Certificate loadCertificate(String b64cert) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(b64cert);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(decoded)
        );
    }

    public static String certToBase64(X509Certificate cert) throws Exception {
        byte[] encoded = cert.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }
}