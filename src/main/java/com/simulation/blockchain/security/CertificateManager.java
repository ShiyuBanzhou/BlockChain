package com.simulation.blockchain.security;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;

public class CertificateManager {
    public static void importCertificate(
            String alias, String certFilePath,
            String trustStorePath, String trustStorePwd
    ) throws Exception {
        try (FileInputStream fis = new FileInputStream(trustStorePath)) {
            KeyStore ts = KeyStore.getInstance("JKS");
            ts.load(fis, trustStorePwd.toCharArray());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            try (FileInputStream certFis = new FileInputStream(certFilePath)) {
                java.security.cert.Certificate cert = cf.generateCertificate(certFis);
                ts.setCertificateEntry(alias, cert);
            }
            try (FileOutputStream fos = new FileOutputStream(trustStorePath)) {
                ts.store(fos, trustStorePwd.toCharArray());
            }
        }
    }

    public static void removeCertificate(
            String alias, String trustStorePath, String trustStorePwd
    ) throws Exception {
        try (FileInputStream fis = new FileInputStream(trustStorePath)) {
            KeyStore ts = KeyStore.getInstance("JKS");
            ts.load(fis, trustStorePwd.toCharArray());
            ts.deleteEntry(alias);
            try (FileOutputStream fos = new FileOutputStream(trustStorePath)) {
                ts.store(fos, trustStorePwd.toCharArray());
            }
        }
    }
}
