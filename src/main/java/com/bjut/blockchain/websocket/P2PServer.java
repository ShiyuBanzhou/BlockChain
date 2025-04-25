package com.bjut.blockchain.websocket;

import java.net.InetSocketAddress;

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

	public void initP2PServer(int port) {
		WebSocketServer socketServer = new WebSocketServer(new InetSocketAddress(port)) {

			/**
			 * 连接建立后触发
			 */
			@Override
			public void onOpen(WebSocket webSocket, ClientHandshake clientHandshake) {
				p2pService.getSockets().add(webSocket);
			}

			/**
			 * 连接关闭后触发
			 */
			@Override
			public void onClose(WebSocket webSocket, int i, String s, boolean b) {
				p2pService.getSockets().remove(webSocket);
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
				System.out.println("connection failed to address:" + webSocket.getRemoteSocketAddress());
			}

			@Override
			public void onStart() {

			}

		};
		socketServer.start();
		System.out.println("listening websocket p2p port on: " + port);
	}

}
