package com.bjut.blockchain.web.util;

import com.bjut.blockchain.websocket.P2PServer;
import com.codahale.shamir.Scheme;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;

public class ShamirUtil {

    public static String getShamir() {
        Scheme scheme = new Scheme(new SecureRandom(), P2PServer.nodeNum, P2PServer.nodeNum-1);
        byte[] secret = KeyAgreementUtil.keyAgreementValue.getBytes(StandardCharsets.UTF_8);
        Map<Integer, byte[]> parts = scheme.split(secret);
        BlockCache blockCache=new BlockCache();
        //todo 获取节点位置
        int i=blockCache.getP2pport()%7000-1;
        return CryptoUtil.byte2Hex(parts.get(i));
        //byte[] recovered = scheme.join(parts);
        //System.out.println(new String(recovered, StandardCharsets.UTF_8));
    }
}
