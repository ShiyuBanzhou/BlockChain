package com.bjut.blockchain.web.service;


import com.alibaba.fastjson.JSON;
import com.bjut.blockchain.web.model.Message;
import com.bjut.blockchain.web.util.BlockConstant;
import com.bjut.blockchain.web.util.CryptoUtil;
import com.bjut.blockchain.web.util.KeyAgreementUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.PublicKey;

/**
 * @author l
 */
@Component
public class NodeJoinAndQuit {

    @Autowired
    P2PService p2PService;

    public void agreement(){
        try {
            KeyAgreementUtil.keyAgreementValue=null;
            Thread.sleep(800);
            CAImpl.createNodeKeyPair();
            PublicKey publicKey = CAImpl.getNodeKeyPair().getPublic();
            // 获取公钥的字节数组
            byte[] publicKeyBytes = publicKey.getEncoded();
            // 将字节数组转换为十六进制字符串
            String publicKeyHex = CryptoUtil.byte2Hex(publicKeyBytes);
            Message message=new Message(BlockConstant.KEY_AGREEMENT,publicKeyHex);
            //todo 节点退出显示p2PService为null
            if (p2PService == null) {
                System.out.println("p2PService为null");
                p2PService= new P2PService();
            }
            p2PService.broatcast(JSON.toJSONString(message));
        } catch (InterruptedException e) {
        throw new RuntimeException(e);
    }
    }

    public void join(){
        //todo 派发密钥
        System.out.println("节点加入派发密钥");
        Message msg = new Message(BlockConstant.DISTRIBUTE_KEY,KeyAgreementUtil.keyAgreementValue);
        p2PService.broatcast(JSON.toJSONString(msg));
    }

    public void selfQuit(){
        Message msg = new Message();
        msg.setType(BlockConstant.NODE_QUIT);
        p2PService.broatcast(JSON.toJSONString(msg));
    }
}
