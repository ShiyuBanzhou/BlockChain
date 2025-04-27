# 证书获取和http接口信息
请求路径 "/ca"
请求方法 POST
说明：获取用户指定参数的CA证书
请求参数
    String userPublicKey  用户公钥的Base64 编码的字符串（下面是转换函数）
    String userDN  用户DN 例如 "CN=User, OU=User, O=User, L=User, ST=User, C=User"
    请求体示例：userPublicKey={userPublicKeyStr}&userDN={userDN}
响应内容
    CAString String CA证书的Base64编码字符串

请求路径 "/root-ca"
请求方法 GET
说明：获取根CA证书
响应内容 ：rootCAString String CA根证书的Base64编码字符串


# 证书认证
证书认证函数位于com.bjut.ca.Util.CertificateValidator
说明：
   （1） boolean validateCertificate(X509Certificate certificate, X509Certificate rootCertificate)
        方法用于验证证书是否合法
        certificate 待验证的X509证书对象
        rootCertificate 根X509证书对象，用于验证给定证书的签名
        如果证书有效且签名验证成功，则返回true；否则返回false

   （2） boolean validateCertificateByString(String certificate, String rootCertificate)
         方法用于验证证书（Base64编码字符串格式）是否合法
        certificate 以Base64编码字符串格式表示的待验证证书内容
        rootCertificate 以Base64编码字符串格式的根证书内容
        如果证书有效且签名验证成功，则返回true；否则返回false

# 相关函数
/**
 将 PublicKey 对象转换为 Base64 编码的字符串
 @param publicKey 要转换的 PublicKey 对象
 @return 转换后的 Base64 编码字符串，如果转换失败则返回 null
  */
  public static String publicKeyToString(PublicKey publicKey) {
     if (publicKey == null) {
        return null;
      }
  try {
      byte[] publicKeyBytes = publicKey.getEncoded();
      return Base64.getEncoder().encodeToString(publicKeyBytes);
    } catch (Exception e) {
      e.printStackTrace();
      return null;
   }
}

/**
 将 Base64 编码的字符串转换为 X509Certificate 对象

 @param certificateBase64 Base64 编码的证书字符串
 @return X509Certificate 对象
 @throws CertificateException 如果证书加载失败
*/
public static X509Certificate stringToCertificate(String certificateBase64) throws CertificateException {
byte[] certificateBytes = Base64.getDecoder().decode(certificateBase64);
CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
}
