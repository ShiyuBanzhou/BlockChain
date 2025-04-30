//package com.bjut.blockchain.web.Aspect;
//
//
//
//import com.bjut.blockchain.web.service.CAImpl;
//import com.bjut.blockchain.web.util.CertificateValidator;
//import com.bjut.blockchain.web.util.Coder;
//import com.bjut.blockchain.web.util.KeyAgreementUtil;
//import org.aspectj.lang.JoinPoint;
//import org.aspectj.lang.annotation.Aspect;
//import org.aspectj.lang.annotation.Before;
//import org.aspectj.lang.annotation.Pointcut;
//import org.springframework.stereotype.Component;
//
//@Aspect
//@Component
//public class BroadcastAspect {
//
//    // 定义切入点，匹配com.bjut.blockchain.web.service.P2PService中的broadcast方法
//    @Pointcut("execution(public void com.bjut.blockchain.web.service.P2PService.broatcast(String))")
//    public void broadcastPointcut() {}
//
//    // 在broadcast方法执行之前执行
//    @Before("broadcastPointcut() && args(message)")
//    public void processMessage(JoinPoint joinPoint, String message) {
//        try {
//            // 获取证书字符串
//            String certificateStr = CAImpl.getCertificateStr();
//            // 拼接消息和证书
//            message = message + "*&*" + certificateStr;
//            // 使用AES加密消息
//            message = Coder.encryptAES(message, KeyAgreementUtil.keyAgreementValue);
//            // 修改方法参数
//            joinPoint.getArgs()[0] = message;
//        } catch (Exception e) {
//            throw new RuntimeException("Error processing message", e);
//        }
//    }
//}