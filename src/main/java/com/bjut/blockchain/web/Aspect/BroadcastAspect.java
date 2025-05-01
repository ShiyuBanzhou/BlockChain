package com.bjut.blockchain.web.Aspect;



import com.bjut.blockchain.web.service.CAImpl;
import com.bjut.blockchain.web.util.CertificateValidator;
import com.bjut.blockchain.web.util.Coder;
import com.bjut.blockchain.web.util.KeyAgreementUtil;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.java_websocket.WebSocket;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class BroadcastAspect {

    // 定义切入点，匹配com.bjut.blockchain.web.service.P2PService中的write方法
    @Pointcut("execution(public void com.bjut.blockchain.web.service.P2PService.write(..))")
    public void writePointcut() {}

    // 在write方法执行之前执行
    //@Around("writePointcut() && args(ws, message)")
    public void processMessage(JoinPoint joinPoint, WebSocket ws, String message) {
        try {
            // 获取证书字符串
            String certificateStr = CAImpl.getCertificateStr();
            // 拼接消息和证书
            message = message + "*&*" + certificateStr;
            //密钥不为空才加密信息
            if(KeyAgreementUtil.keyAgreementValue!=null && !message.contains(KeyAgreementUtil.keyAgreementValue)){
               // 使用AES加密消息
                message = Coder.encryptAES(message, KeyAgreementUtil.keyAgreementValue);
            }
            // 修改方法参数
            joinPoint.getArgs()[1] = message;
            System.out.println("Processed message: " + message);
        } catch (Exception e) {
            System.out.println("Error processing message: " + e.getMessage());
            throw new RuntimeException("Error processing message", e);
        }
    }

   public static String processMessage(String message) {
       try {
           // 获取证书字符串
           String certificateStr = CAImpl.getCertificateStr();
           // 拼接消息和证书
           message = message + "*&*" + certificateStr;
           //密钥不为空才加密信息
           if(KeyAgreementUtil.keyAgreementValue!=null && !message.contains(KeyAgreementUtil.keyAgreementValue)){
               // 使用AES加密消息
               message = Coder.encryptAES(message, KeyAgreementUtil.keyAgreementValue);
           }
           return message;
       } catch (Exception e) {
           System.out.println("Error processing message: " + e.getMessage());
           throw new RuntimeException("Error processing message", e);
       }
   }
}