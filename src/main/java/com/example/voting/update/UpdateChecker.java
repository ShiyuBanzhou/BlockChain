package com.example.voting.update;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * 验证软件更新包签名与版本
 */
public class UpdateChecker {
    private PublicKey devPubKey;
    private String currentVersion;

    public UpdateChecker(PublicKey devPubKey, String currentVersion) {
        this.devPubKey = devPubKey;
        this.currentVersion = currentVersion;
    }

    /** 验证更新文件和签名 */
    public boolean verifyUpdate(String filePath, String sigBase64, String newVersion) {
        try {
            byte[] data = Files.readAllBytes(Paths.get(filePath));
            // 1. 签名验证
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(devPubKey);
            sig.update(data);
            if (!sig.verify(Base64.getDecoder().decode(sigBase64))) {
                System.err.println("更新签名无效！");
                return false;
            }
            // 2. 版本检查
            if (newVersion.compareTo(currentVersion) <= 0) {
                System.err.println("新版本不高于当前版本！");
                return false;
            }
            System.out.println("更新 " + newVersion + " 验证通过。");
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
