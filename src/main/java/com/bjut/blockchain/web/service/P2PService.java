package com.bjut.blockchain.web.service;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import com.bjut.blockchain.web.Aspect.BroadcastAspect;
import com.bjut.blockchain.web.Aspect.HandleMessageAspect;
import com.bjut.blockchain.web.util.KeyAgreementUtil;
import org.java_websocket.WebSocket;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import com.alibaba.fastjson.JSON;
import com.bjut.blockchain.web.model.Block;
import com.bjut.blockchain.web.model.Message;
import com.bjut.blockchain.web.util.BlockCache;
import com.bjut.blockchain.web.util.BlockConstant;
import com.bjut.blockchain.websocket.P2PClient;
import com.bjut.blockchain.websocket.P2PServer;

/**
 * p2p网络服务类
 * 
 * @author Jared Jia
 *
 */
@Service
public class P2PService implements ApplicationRunner {
	
	@Autowired
	BlockService blockService;
	
	@Autowired
	BlockCache blockCache;
	
	@Autowired
	P2PServer p2PServer;
	
	@Autowired
	P2PClient p2PClient;

	@Autowired
	NodeJoinAndQuit nodeJoinAndQuit;

	@Autowired
	KeyAgreementUtil keyAgreementUtil;

	/**
	 * 客户端和服务端共用的消息处理方法
	 * @param webSocket
	 * @param msg
	 * @param sockets
	 */
	public void handleMessage(WebSocket webSocket, String msg, List<WebSocket> sockets) {
		msg= HandleMessageAspect.processMessage(msg);
		if(msg==null) {
                   return;
                }
		try {
			Message message = JSON.parseObject(msg, Message.class);
			System.out.println("接收到IP地址为：" +webSocket.getRemoteSocketAddress().getAddress().toString()
					+"，端口号为："+ webSocket.getRemoteSocketAddress().getPort() + "的p2p消息："
			        + JSON.toJSONString(message));
			switch (message.getType()) {
			//客户端请求查询最新的区块:1
			case BlockConstant.QUERY_LATEST_BLOCK:
				write(webSocket, responseLatestBlockMsg());//服务端调用方法返回最新区块:2
				break;
			//接收到服务端返回的最新区块:2
			case BlockConstant.RESPONSE_LATEST_BLOCK:
				handleBlockResponse(message.getData(), sockets);
				break;
			//客户端请求查询整个区块链:3
			case BlockConstant.QUERY_BLOCKCHAIN:
				write(webSocket, responseBlockChainMsg());//服务端调用方法返回最新区块:4
				break;
			//直接接收到其他节点发送的整条区块链信息:4
			case BlockConstant.RESPONSE_BLOCKCHAIN:
				handleBlockChainResponse(message.getData(), sockets);
				break;
			//密钥交换:5
			case BlockConstant.KEY_AGREEMENT:
			    //todo 密钥交换
				System.out.println("节点密钥交换"+message.getData());
				keyAgreementUtil.agreementKey(message.getData());
				break;
			//节点退出：6
			case BlockConstant.NODE_QUIT:
				nodeJoinAndQuit.agreement();
				break;
			//派发密钥：7
			case BlockConstant.DISTRIBUTE_KEY:
			    //todo 分布式密钥
				System.out.println("节点接收密钥"+message.getData());
				if(KeyAgreementUtil.keyAgreementValue==null){
					KeyAgreementUtil.keyAgreementValue=message.getData();
				}
				break;

			}
		} catch (Exception e) {
			System.out.println("处理IP地址为：" +webSocket.getRemoteSocketAddress().getAddress().toString()
				+"，端口号为："+ webSocket.getRemoteSocketAddress().getPort() + "的p2p消息错误:" 
				+ e.getMessage());
		}
	}

	/**
	 * 处理其它节点发送过来的区块信息
	 * @param blockData
	 * @param sockets
	 */
	public synchronized void handleBlockResponse(String blockData, List<WebSocket> sockets) {
		//反序列化得到其它节点的最新区块信息
		Block latestBlockReceived = JSON.parseObject(blockData, Block.class);
		//当前节点的最新区块
		Block latestBlock = blockCache.getLatestBlock();
		
		if (latestBlockReceived != null) {
			if(latestBlock != null) {
				//如果接收到的区块高度比本地区块高度大的多
				if(latestBlockReceived.getIndex() > latestBlock.getIndex() + 1) {
					broatcast(queryBlockChainMsg());
					System.out.println("重新查询所有节点上的整条区块链");
				}else if (latestBlockReceived.getIndex() > latestBlock.getIndex() && 
						latestBlock.getHash().equals(latestBlockReceived.getPreviousHash())) {
					if (blockService.addBlock(latestBlockReceived)) {
						broatcast(responseLatestBlockMsg());
					}
					System.out.println("将新接收到的区块加入到本地的区块链");
				}
			}else if(latestBlock == null) {
				broatcast(queryBlockChainMsg());
				System.out.println("重新查询所有节点上的整条区块链");
			}
		}
	}
	
	/**
	 * 处理其它节点发送过来的区块链信息
	 * @param blockData
	 * @param sockets
	 */
	public synchronized void handleBlockChainResponse(String blockData, List<WebSocket> sockets) {
		//反序列化得到其它节点的整条区块链信息
		List<Block> receiveBlockchain = JSON.parseArray(blockData, Block.class);
		if(!CollectionUtils.isEmpty(receiveBlockchain) && blockService.isValidChain(receiveBlockchain)) {
			//根据区块索引先对区块进行排序
			Collections.sort(receiveBlockchain, new Comparator<Block>() {
				public int compare(Block block1, Block block2) {
					return block1.getIndex() - block2.getIndex();
				}
			});
			
			//其它节点的最新区块
			Block latestBlockReceived = receiveBlockchain.get(receiveBlockchain.size() - 1);
			//当前节点的最新区块
			Block latestBlock = blockCache.getLatestBlock();
			
			if(latestBlock == null) {
				//替换本地的区块链
				blockService.replaceChain(receiveBlockchain);
			}else {
				//其它节点区块链如果比当前节点的长，则处理当前节点的区块链
				if (latestBlockReceived.getIndex() > latestBlock.getIndex()) {
					if (latestBlock.getHash().equals(latestBlockReceived.getPreviousHash())) {
						if (blockService.addBlock(latestBlockReceived)) {
							broatcast(responseLatestBlockMsg());
						}
						System.out.println("将新接收到的区块加入到本地的区块链");
					} else {
						// 用长链替换本地的短链
						blockService.replaceChain(receiveBlockchain);
					}
				}
			}
		}
	}
	
	/**
	 * 全网广播消息
	 * @param message
	 */
	public void broatcast(String message) {
		List<WebSocket> socketsList = this.getSockets();
		if (CollectionUtils.isEmpty(socketsList)) {
			return;
		}
		System.out.println("======全网广播消息开始：");
		for (WebSocket socket : socketsList) {
			this.write(socket, message);
		}
		System.out.println("======全网广播消息结束");
	}
	
	/**
	 * 向其它节点发送消息
	 * @param ws
	 * @param message
	 */
	public void write(WebSocket ws, String message) {
		message= BroadcastAspect.processMessage(message);
		System.out.println("发送给IP地址为：" +ws.getRemoteSocketAddress().getAddress().toString() 
			+ "，端口号为："+ws.getRemoteSocketAddress().getPort() + " 的p2p消息:" + message);
		ws.send(message);
	}

	/**
	 * 查询整条区块链
	 * @return
	 */
	public String queryBlockChainMsg() {
		return JSON.toJSONString(new Message(BlockConstant.QUERY_BLOCKCHAIN));
	}
	
	/**
	 * 返回整条区块链数据
	 * @return
	 */
	public String responseBlockChainMsg() {
		Message msg = new Message();
		msg.setType(BlockConstant.RESPONSE_BLOCKCHAIN);
		msg.setData(JSON.toJSONString(blockCache.getBlockChain()));
		return JSON.toJSONString(msg);
	}

	/**
	 * 查询最新的区块
	 * @return
	 */
	public String queryLatestBlockMsg() {
		return JSON.toJSONString(new Message(BlockConstant.QUERY_LATEST_BLOCK));
	}
	
	/**
	 * 返回最新的区块
	 * @return
	 */
	public String responseLatestBlockMsg() {
		Message msg = new Message();
		msg.setType(BlockConstant.RESPONSE_LATEST_BLOCK);
		Block b = blockCache.getLatestBlock();
		msg.setData(JSON.toJSONString(b));
		return JSON.toJSONString(msg);
	}
	
	public List<WebSocket> getSockets(){
		return blockCache.getSocketsList();
	}

	@Override
	public void run(ApplicationArguments args) throws Exception {
		// 启动 P2P 服务器
		p2PServer.initP2PServer(blockCache.getP2pport());

		// 连接到配置的初始对等节点
		List<String> initialPeers = blockCache.getInitialPeers(); // 获取地址列表
		if (initialPeers != null) {
			for (String peerAddress : initialPeers) { // 遍历列表
				p2PClient.connectToPeer(peerAddress); // 尝试连接每个节点
			}
		}

		System.out.println("*****难度系数******"+blockCache.getDifficulty());
		System.out.println("*****端口号******"+blockCache.getP2pport());
		System.out.println("*****节点地址列表******"+blockCache.getInitialPeers()); // 输出地址列表
	}
	
}
