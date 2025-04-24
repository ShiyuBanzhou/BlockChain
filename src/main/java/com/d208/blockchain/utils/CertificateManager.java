package com.d208.blockchain.utils;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

public class CertificateManager {

    private static final String KEYSTORE_TYPE = "JKS"; // Or "PKCS12"
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String KEY_ALGORITHM = "EC"; // Match ECDSAUtils

    static {
        // Add BouncyCastle provider statically for cryptographic operations
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generates a KeyPair using the specified algorithm.
     * Reuses logic similar to ECDSAUtils or calls it directly.
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        // Use existing ECDSAUtils method if preferred and compatible
        // return ECDSAUtils.getKeyPair();

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(256); // EC key size
        return keyPairGen.generateKeyPair();
    }

    /**
     * Generates a self-signed X.509 Certificate.
     *
     * @param keyPair The KeyPair (public and private key).
     * @param subjectDN The Distinguished Name for the certificate subject (e.g., "CN=Node1, OU=BlockchainDept, O=MyOrg, C=US").
     * @param daysValidity Number of days the certificate should be valid.
     * @return The generated X509Certificate.
     * @throws Exception If certificate generation fails.
     */
    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDN, int daysValidity) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + daysValidity * 24L * 60L * 60L * 1000L); // Valid for specified days

        X500Name subject = new X500Name(subjectDN);
        // Serial number should be unique, using timestamp for simplicity here
        BigInteger serialNumber = BigInteger.valueOf(now);

        // Issuer is the same as subject for self-signed certificates
        X500Name issuer = subject;

        // Use the public key from the KeyPair
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Build the certificate
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                startDate,
                endDate,
                subject,
                publicKey
        );

        // Sign the certificate with the private key
        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(privateKey);

        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC") // Specify BouncyCastle provider
                .getCertificate(certBuilder.build(contentSigner));

        // Verify the certificate (optional sanity check)
        certificate.verify(publicKey);

        return certificate;
    }

    /**
     * Creates or loads a KeyStore and saves the private key and certificate.
     * If the KeyStore file exists, it loads it; otherwise, it creates a new one.
     *
     * @param keyStoreFile Path to the KeyStore file (e.g., "node0.jks").
     * @param keyStorePassword Password for the KeyStore integrity and entry.
     * @param alias Alias for the key entry (e.g., "node0_key").
     * @param privateKey The private key to store.
     * @param certificate The certificate to store.
     * @throws Exception If KeyStore operations fail.
     */
    public static void saveKeyAndCertificate(String keyStoreFile, char[] keyStorePassword, String alias, PrivateKey privateKey, X509Certificate certificate) throws Exception {
        KeyStore keyStore = loadOrInitializeKeyStore(keyStoreFile, keyStorePassword);

        // Store the private key and certificate chain (just one cert here)
        Certificate[] chain = { certificate };
        keyStore.setKeyEntry(alias, privateKey, keyStorePassword, chain);

        // Save the KeyStore to the file
        try (FileOutputStream fos = new FileOutputStream(keyStoreFile)) {
            keyStore.store(fos, keyStorePassword);
        }
    }

    /**
     * Loads a PrivateKey from a KeyStore.
     *
     * @param keyStoreFile Path to the KeyStore file.
     * @param keyStorePassword Password for the KeyStore.
     * @param alias Alias of the key entry.
     * @return The loaded PrivateKey.
     * @throws Exception If KeyStore operations fail or entry not found.
     */
    public static PrivateKey loadPrivateKey(String keyStoreFile, char[] keyStorePassword, String alias) throws Exception {
        KeyStore keyStore = loadOrInitializeKeyStore(keyStoreFile, keyStorePassword);
        // Password for the key entry is the same as the keystore password here
        Key key = keyStore.getKey(alias, keyStorePassword);
        if (!(key instanceof PrivateKey)) {
            throw new KeyStoreException("Entry for alias '" + alias + "' is not a private key.");
        }
        return (PrivateKey) key;
    }

    /**
     * Loads a Certificate from a KeyStore.
     *
     * @param keyStoreFile Path to the KeyStore file.
     * @param keyStorePassword Password for the KeyStore.
     * @param alias Alias of the certificate entry.
     * @return The loaded Certificate.
     * @throws Exception If KeyStore operations fail or entry not found.
     */
    public static Certificate loadCertificate(String keyStoreFile, char[] keyStorePassword, String alias) throws Exception {
        KeyStore keyStore = loadOrInitializeKeyStore(keyStoreFile, keyStorePassword);
        Certificate cert = keyStore.getCertificate(alias);
        if (cert == null) {
            throw new KeyStoreException("Certificate for alias '" + alias + "' not found.");
        }
        return cert;
    }


    /**
     * Helper method to load an existing KeyStore or create a new one if it doesn't exist.
     */
    private static KeyStore loadOrInitializeKeyStore(String keyStoreFile, char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        java.io.File file = new java.io.File(keyStoreFile);

        if (file.exists()) {
            // Load existing KeyStore
            try (FileInputStream fis = new FileInputStream(file)) {
                keyStore.load(fis, password);
            }
        } else {
            // Initialize a new KeyStore (needs to be saved later)
            keyStore.load(null, password); // Pass null stream to initialize
        }
        return keyStore;
    }

    /**
     * Helper to get PublicKey string in Base64 format from a Certificate.
     * (Similar to ECDSAUtils.getPubKeyStr but takes Certificate)
     */
    public static String getPubKeyStr(Certificate certificate) {
        return Base64.getEncoder().encodeToString(certificate.getPublicKey().getEncoded());
    }
}