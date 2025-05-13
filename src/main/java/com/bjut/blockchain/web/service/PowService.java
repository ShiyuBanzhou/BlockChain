package com.bjut.blockchain.web.service;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.alibaba.fastjson.JSON;
import com.bjut.blockchain.web.model.Block;
import com.bjut.blockchain.web.model.Message;
import com.bjut.blockchain.web.model.Transaction;
import com.bjut.blockchain.web.util.BlockCache;
import com.bjut.blockchain.web.util.BlockConstant;
import com.bjut.blockchain.web.util.CommonUtil;

/**
 * 共识机制
 * 采用POW即工作量证明实现共识
 * @author Administrator
 *
 */
@Service
public class PowService {

	@Autowired
	BlockCache blockCache;
	
	@Autowired
	BlockService blockService;
	
	@Autowired
	P2PService p2PService;
	
	/**
	 * 通过“挖矿”进行工作量证明，实现节点间的共识
	 * 
	 * @return
	 * @throws UnknownHostException
	 */
	public Block mine(){
		// 从 BlockService 获取交易池中的交易
		List<Transaction> transactionsToPackage = new ArrayList<>(blockService.getTransactionPool()); // 获取副本

		if (transactionsToPackage.isEmpty()) {
			// 如果没有交易，可以创建一个包含默认信息的区块，或者等待有交易
			System.out.println("交易池为空，创建一个包含节点信息的区块");
			List<Transaction> defaultTxs = new ArrayList<>();
			Transaction tsa1 = new Transaction();
			tsa1.setId(CommonUtil.generateUuid()); // 使用 CommonUtil 生成ID
			tsa1.setTimestamp(System.currentTimeMillis());
			tsa1.setData("这是IP为：" + CommonUtil.getLocalIp() + "，端口号为：" + blockCache.getP2pport() + "的节点挖矿生成的区块 (无用户交易)");
			defaultTxs.add(tsa1);
			Transaction tsa2 = new Transaction();
			tsa2.setId(CommonUtil.generateUuid());
			tsa2.setTimestamp(System.currentTimeMillis());
			tsa2.setData("区块链高度为：" + (blockCache.getLatestBlock().getIndex() + 1));
			defaultTxs.add(tsa2);
			transactionsToPackage.addAll(defaultTxs);
		} else {
			System.out.println("从交易池获取到 " + transactionsToPackage.size() + " 条交易进行打包。");
			// 清空已打包的交易 (可选，取决于你的交易池管理策略)
			blockService.clearTransactionPool(); // 你需要在 BlockService 中实现此方法
		}


		String newBlockHash = "";
		int nonce = 0;
		long start = System.currentTimeMillis();
		System.out.println("开始挖矿");
		Block latestBlock = blockCache.getLatestBlock();
		if (latestBlock == null && blockCache.getBlockChain().isEmpty()) {
			System.out.println("区块链为空，请先创建创世区块！");
			// 或者在这里自动创建创世区块
			// blockService.createGenesisBlock();
			// latestBlock = blockCache.getLatestBlock();
			// if(latestBlock == null) return null; // 无法继续
			return null;
		}


		while (true) {
			newBlockHash = blockService.calculateHash(latestBlock.getHash(), transactionsToPackage, nonce);
			if (blockService.isValidHash(newBlockHash)) { // 假设难度是固定的，如 "0000"
				System.out.println("挖矿完成，正确的hash值：" + newBlockHash);
				System.out.println("挖矿耗费时间：" + (System.currentTimeMillis() - start) + "ms");
				break;
			}
			// System.out.println("第"+(nonce+1)+"次尝试计算的hash值：" + newBlockHash); // 可以取消注释以查看过程
			nonce++;
		}

		Block block = blockService.createNewBlock(nonce, latestBlock.getHash(), newBlockHash, transactionsToPackage);

		if (block != null) {
			Message msg = new Message();
			msg.setType(BlockConstant.RESPONSE_LATEST_BLOCK);
			msg.setData(JSON.toJSONString(block));
			p2PService.broatcast(JSON.toJSONString(msg));
		}
		return block;
	}
	
}
