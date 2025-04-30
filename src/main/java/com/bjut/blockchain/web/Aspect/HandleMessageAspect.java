//package com.bjut.blockchain.web.Aspect;
//
//import com.bjut.blockchain.web.util.CertificateValidator;
//import com.bjut.blockchain.web.util.Coder;
//import com.bjut.blockchain.web.util.KeyAgreementUtil;
//import org.aspectj.lang.JoinPoint;
//import org.aspectj.lang.annotation.Aspect;
//import org.aspectj.lang.annotation.Before;
//import org.aspectj.lang.annotation.Pointcut;
//import org.java_websocket.WebSocket;
//import org.springframework.stereotype.Component;
//
//import java.util.List;
//
//@Aspect
//@Component
//public class HandleMessageAspect {
//
//    // 定义切入点，匹配com.bjut.blockchain.web.service.P2PService中的handleMessage方法
//    @Pointcut("execution(public void com.bjut.blockchain.web.service.P2PService.handleMessage(..))")
//    public void handleMessagePointcut() {}
//
//    // 在handleMessage方法执行之前执行
//    @Before("handleMessagePointcut() && args(webSocket, msg, sockets)")
//    public void processMessage(JoinPoint joinPoint, WebSocket webSocket, String msg, List<WebSocket> sockets) {
//        try {
//            // 解密消息
//            msg = Coder.decryptAES(msg, KeyAgreementUtil.keyAgreementValue);
//            // 分割消息和证书
//            String[] message = msg.split("\\*&\\*");
//            // 验证证书
//            if (CertificateValidator.validateCertificateByString(message[1])) {
//                // 如果证书验证通过，将处理后的消息赋值回方法参数
//                joinPoint.getArgs()[1] = message[0];
//            } else {
//                // 如果证书验证失败，直接返回null
//                System.out.println("证书验证失败");
//                joinPoint.getArgs()[1] = null;
//            }
//        } catch (Exception e) {
//            throw new RuntimeException("Error processing message", e);
//        }
//    }
//}