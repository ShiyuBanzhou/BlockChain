package com.bjut.blockchain.web.controller;

import com.bjut.blockchain.web.service.CAImpl; // 假设 CAImpl 提供了获取证书的方法
import com.bjut.blockchain.web.util.KeyAgreementUtil; // 假设 KeyAgreementUtil 提供了获取密钥协商值的方法
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController; // 修改为 RestController
// import org.springframework.web.bind.annotation.CrossOrigin; // 如果WebConfig中已配置全局CORS，这里通常可以省略

/**
 * 用于处理与证书颁发机构 (CA) 相关操作的 REST 控制器。
 * 所有端点都在 /api/ca 路径下。
 */
@RestController // <--- 修改: 使用 @RestController
@RequestMapping("/api/ca") // <--- 添加: API基础路径
// @CrossOrigin // 如果WebConfig中已配置全局CORS，这里通常可以省略
public class CAController {

    /**
     * 获取证书信息。
     * 路径: GET /api/ca/certificate
     * @return JSON字符串表示的证书信息
     * @throws Exception 如果处理过程中发生错误
     */
    @GetMapping("/certificate") // <--- 修改: 路径更具体 (原 /ca)
    public String getCertificate() throws Exception {
        // 理想情况下，CAImpl 应该是一个注入的Bean，而不是静态调用
        // 例如: @Autowired private CAService caService; return caService.getCertificateMap();
        return CAImpl.getCertificateMap();
    }

    /**
     * 获取密钥协商值 (或密码)。
     * 路径: GET /api/ca/key-agreement-value
     * @return 字符串表示的密钥协商值
     * @throws Exception 如果处理过程中发生错误
     */
    @GetMapping("/key-agreement-value") // <--- 修改: 路径更具体 (原 /password)
    public String getKeyAgreementValue() throws Exception {
        // 理想情况下，KeyAgreementUtil 的功能也应该通过服务Bean提供
        return KeyAgreementUtil.keyAgreementValue;
    }
}
