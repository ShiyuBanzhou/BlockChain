package com.bjut.ca.server.controller;

import com.bjut.ca.Util.X509CertificateUtil;
import com.bjut.ca.server.impl.CAimpl;
import io.swagger.v3.oas.annotations.Operation; // 确保导入
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam; // 明确使用 @RequestParam
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

@RestController
// 如果您的Controller有统一的前缀，例如 "/ca-api", 请在此处或application.yml中配置
// @RequestMapping("/ca-api")
public class CA {

    @Autowired
    CAimpl cAimpl; // 驼峰命名规范，变量名首字母小写

    /**
     * 获取用户指定参数的CA证书
     *
     * @param userPublicKey 用户公钥，用于生成CA证书
     * @param userDN 用户DN（Distinguished Name），用于标识用户信息
     * @return 返回生成的CA证书的字符串表示
     * @throws Exception 如果生成CA证书过程中出现异常，则抛出此异常
     */
    @Operation(summary = "获取用户证书", description = "根据用户公钥和DN信息颁发X.509证书")
    @ApiResponse(responseCode = "200", description = "成功颁发证书", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String.class)))
    @ApiResponse(responseCode = "400", description = "无效的请求参数")
    @ApiResponse(responseCode = "500", description = "服务器内部错误")
    @PostMapping("/ca/certificate") // 路径调整为更具体，例如 /ca/certificate
    public String getCertificate(
            @Parameter(description="用户公钥 (Base64编码)") @RequestParam String userPublicKey,
            @Parameter(description="用户DN (例如 CN=User,O=Org,C=CN)") @RequestParam String userDN) throws Exception {
        // Spring MVC 会自动处理URL解码，所以空格通常不需要手动替换为"+"
        // userPublicKey = userPublicKey.replace(" ", "+");
        X509Certificate userCertificate = cAimpl.getCA(userPublicKey, userDN);
        String certStr = X509CertificateUtil.certificateToString(userCertificate);
        cAimpl.logger.info("为用户 {} 颁发证书: {}", userDN, certStr.substring(0, Math.min(certStr.length(),100))+"..."); // 日志记录
        return certStr;
    }

    /**
     * 获取根CA证书
     *
     * @return 返回根CA证书的字符串表示
     * @throws Exception 如果获取根CA证书过程中出现异常，则抛出此异常
     */
    @Operation(summary = "获取根CA证书", description = "返回当前CA的根X.509证书")
    @ApiResponse(responseCode = "200", description = "成功获取根证书", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String.class)))
    @ApiResponse(responseCode = "500", description = "服务器内部错误")
    @GetMapping("/ca/root-certificate") // 路径调整
    public String getRootCACertificate() throws Exception {
        X509Certificate rootCert = cAimpl.getCACertificate();
        return X509CertificateUtil.certificateToString(rootCert);
    }

    /**
     * 下载最新的证书吊销列表 (CRL)。
     * Downloads the latest Certificate Revocation List (CRL).
     * @return ResponseEntity 包含CRL的DER编码字节或错误信息。
     */
    @Operation(summary = "下载证书吊销列表 (CRL)", description = "返回DER编码的最新CRL")
    @ApiResponse(responseCode = "200", description = "成功获取CRL", content = @Content(mediaType = "application/pkix-crl"))
    @ApiResponse(responseCode = "500", description = "生成CRL时发生服务器内部错误")
    @GetMapping(value = "/ca/crl", produces = "application/pkix-crl") // 标准的CRL MIME类型
    public ResponseEntity<byte[]> downloadCRL() {
        try {
            X509CRL crl = cAimpl.generateCRL();
            byte[] crlBytes = crl.getEncoded(); // 获取DER编码的CRL

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.valueOf("application/pkix-crl"));
            headers.setContentDispositionFormData("attachment", "latest.crl"); // 提示浏览器下载
            headers.setContentLength(crlBytes.length);

            cAimpl.logger.info("提供CRL下载，大小: {} bytes, CRL Number (from CAimpl): {}", crlBytes.length, cAimpl.crlNumber); // 使用CAimpl的crlNumber
            return new ResponseEntity<>(crlBytes, headers, HttpStatus.OK);
        } catch (Exception e) {
            cAimpl.logger.error("生成或提供CRL时发生错误: {}", e.getMessage(), e);
            // 返回一个空的或错误指示的响应体，避免直接暴露异常信息给客户端
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new byte[0]);
        }
    }
}
