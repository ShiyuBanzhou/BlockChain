package com.bjut.blockchain.websocket;

import java.net.InetSocketAddress;
import java.security.PublicKey;

import com.alibaba.fastjson.JSON;
import com.bjut.blockchain.web.model.Message;
import com.bjut.blockchain.web.service.CAImpl;
import com.bjut.blockchain.web.service.NodeJoinAndQuit;
import com.bjut.blockchain.web.util.BlockConstant;
import com.bjut.blockchain.web.util.CryptoUtil;
import com.bjut.blockchain.web.util.KeyAgreementUtil;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.bjut.blockchain.web.service.P2PService;

/**
 * p2p服务端
 * 
 * @author Jared Jia
 *
 */
@Component
public class P2PServer {

	@Autowired
	P2PService p2pService;

	@Autowired
	NodeJoinAndQuit nodeJoinAndQuit;

	public static int nodeNum=1;

	public void initP2PServer(int port) {
		WebSocketServer socketServer = new WebSocketServer(new InetSocketAddress(port)) {

			/**
			 * 连接建立后触发
			 */
			@Override
			public void onOpen(WebSocket webSocket, ClientHandshake clientHandshake) {
				p2pService.getSockets().add(webSocket);
				nodeNum++;
				System.out.println("节点数量:"+nodeNum);
				if(nodeNum==2){
					nodeJoinAndQuit.agreement();
				}else if(KeyAgreementUtil.keyAgreementValue!=null){
					nodeJoinAndQuit.join();
				}else{
					sendPublicKey();
				}
				
			}

			/**
			 * 连接关闭后触发
			 */
			@Override
			public void onClose(WebSocket webSocket, int i, String s, boolean b) {
				p2pService.getSockets().remove(webSocket);
				nodeNum--;
				System.out.println("关闭连接 剩余节点数量："+nodeNum);
				//nodeJoinAndQuit.agreement();
				System.out.println("connection closed to address:" + webSocket.getRemoteSocketAddress());
			}

			/**
			 * 接收到客户端消息时触发
			 */
			@Override
			public void onMessage(WebSocket webSocket, String msg) {
				//作为服务端，业务逻辑处理
				p2pService.handleMessage(webSocket, msg, p2pService.getSockets());
			}

			/**
			 * 发生错误时触发
			 */
			@Override
			public void onError(WebSocket webSocket, Exception e) {
				p2pService.getSockets().remove(webSocket);
				e.printStackTrace();
				System.out.println("connection failed to address:" + webSocket.getRemoteSocketAddress());
			}

			@Override
			public void onStart() {

			}

		};
		socketServer.start();
		System.out.println("listening websocket p2p port on: " + port);
	}

	public void sendPublicKey() {
        try {
            Thread.sleep(300);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        String publicKeyHex = CryptoUtil.byte2Hex(CAImpl.getKeyPair().getPublic().getEncoded());
		Message message=new Message(BlockConstant.KEY_AGREEMENT,publicKeyHex);
		p2pService.broatcast(JSON.toJSONString(message));
	}

}
