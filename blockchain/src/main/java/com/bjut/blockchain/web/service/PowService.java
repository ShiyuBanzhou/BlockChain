package com.bjut.blockchain.web.service;

import com.alibaba.fastjson.JSON;
import com.bjut.blockchain.web.model.Block;
import com.bjut.blockchain.web.model.Message;
import com.bjut.blockchain.web.model.Transaction;
import com.bjut.blockchain.web.util.BlockCache;
import com.bjut.blockchain.web.util.BlockConstant;
import com.bjut.blockchain.web.util.CommonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
// import org.springframework.transaction.annotation.Transactional; // 如果mine本身需要是事务性的

import java.util.ArrayList;
import java.util.List;

/**
 * 共识机制服务。
 * 采用POW (工作量证明) 实现共识。
 */
@Service
public class PowService {

	private static final Logger logger = LoggerFactory.getLogger(PowService.class);

	private final BlockCache blockCache;
	private final BlockService blockService;
	private final P2PService p2pService; // 确保变量名与Autowired匹配 (通常小写开头)

	@Autowired
	public PowService(BlockCache blockCache, BlockService blockService, P2PService p2pService) {
		this.blockCache = blockCache;
		this.blockService = blockService;
		this.p2pService = p2pService;
	}

	/**
	 * 通过“挖矿”进行工作量证明，实现节点间的共识，并打包交易。
	 * @return 成功挖出的新区块，如果失败则返回null。
	 */
	// 如果此方法内的数据库操作（如移除交易）和区块添加需要原子性，可以考虑 @Transactional
	// 但通常挖矿本身是一个较长操作，事务边界可能需要仔细设计。
	// 当前设计：先挖矿，再尝试添加区块，成功添加后再移除交易。
	public Block mine() {
		// 1. 从BlockService获取待处理交易池中的交易 (现在是从数据库获取)
		List<Transaction> transactionsToPackage = blockService.getTransactionPool();

		// 2. 如果交易池为空，可以创建一个包含默认信息的区块
		if (transactionsToPackage.isEmpty()) {
			logger.info("待处理交易池为空，将创建一个包含节点默认信息的区块。");
			transactionsToPackage = new ArrayList<>(); // 确保列表不是null
			Transaction defaultTx1 = new Transaction();
			defaultTx1.setId(CommonUtil.generateUuid());
			defaultTx1.setTimestamp(System.currentTimeMillis());
			String localIp = "未知IP";
			try {
				localIp = CommonUtil.getLocalIp();
			} catch (Exception e) {
				logger.warn("获取本地IP地址失败: {}", e.getMessage());
			}
			defaultTx1.setData(String.format("这是IP为：%s，P2P端口号为：%d 的节点挖出的区块 (无用户交易)",
					localIp, blockCache.getP2pport()));
			transactionsToPackage.add(defaultTx1);

			Block currentLatestBlock = blockCache.getLatestBlock();
			int nextBlockHeight = (currentLatestBlock != null ? currentLatestBlock.getIndex() : 0) + 1;
			Transaction defaultTx2 = new Transaction();
			defaultTx2.setId(CommonUtil.generateUuid());
			defaultTx2.setTimestamp(System.currentTimeMillis());
			defaultTx2.setData("新区块高度为：" + nextBlockHeight);
			transactionsToPackage.add(defaultTx2);
		} else {
			logger.info("从交易池获取到 {} 条交易进行打包。", transactionsToPackage.size());
		}

		// 3. 获取前一个区块的信息以进行挖矿
		Block latestBlock = blockCache.getLatestBlock();
		if (latestBlock == null) {
			// 检查区块链缓存是否完全为空（即连创世块都没有）
			if (blockCache.getBlockChain() == null || blockCache.getBlockChain().isEmpty()) {
				logger.warn("区块链为空（没有创世区块）。请先创建创世区块。挖矿操作中止。");
				// （可选）如果希望在此时自动创建创世块：
				// logger.info("区块链为空，尝试自动创建创世区块...");
				// String genesisJson = blockService.createGenesisBlock();
				// if (genesisJson != null) {
				//     latestBlock = blockCache.getLatestBlock();
				//     if (latestBlock == null) {
				//         logger.error("自动创建创世区块后仍无法获取最新区块，挖矿中止。");
				//         return null;
				//     }
				//     logger.info("创世区块已自动创建，继续挖矿...");
				// } else {
				//     logger.error("自动创建创世区块失败，挖矿中止。");
				//     return null;
				// }
				return null; // 当前策略：没有创世块则不挖
			} else {
				// 这种情况不应该发生：链非空但latestBlock为null。可能BlockCache逻辑有问题。
				logger.error("严重错误：区块链非空但无法获取最新区块 (BlockCache.getLatestBlock()返回null)。挖矿中止。");
				return null;
			}
		}

		// 4. 执行工作量证明 (挖矿)
		logger.info("开始为区块索引 {} (前一区块哈希: {}) 挖矿...", latestBlock.getIndex() + 1, latestBlock.getHash());
		long startTime = System.currentTimeMillis();
		int nonce = 0;
		String newBlockHash;

		while (true) {
			newBlockHash = blockService.calculateHash(latestBlock.getHash(), transactionsToPackage, nonce);
			if (blockService.isValidHash(newBlockHash)) {
				long timeTaken = System.currentTimeMillis() - startTime;
				logger.info("挖矿成功！找到有效哈希: {} (尝试次数: {}, 耗时: {} ms)",
						newBlockHash, nonce + 1, timeTaken);
				break;
			}
			nonce++;
			if (nonce % 500000 == 0 && nonce > 0) { // 每50万次打印一次进度
				logger.debug("挖矿进行中... {} 次尝试", nonce);
			}
		}

		// 5. 创建新的区块对象
		Block newBlock = blockService.createNewBlock(nonce, latestBlock.getHash(), newBlockHash, transactionsToPackage);
		// createNewBlock 内部会设置正确的索引等

		// 6. 将新区块添加到本地区块链 (BlockCache)
		// BlockService.addBlock 会进行区块有效性验证
		if (blockService.addBlock(newBlock)) {
			logger.info("新区块 (索引: {}) 已成功添加到本地区块链缓存。", newBlock.getIndex());

			// 7. **关键**: 区块成功添加后，从待处理交易池中移除这些已打包的交易
			blockService.removeTransactionsFromPool(transactionsToPackage);

			// 8. 广播新区块给网络中的其他节点
			if (p2pService != null) {
				Message msg = new Message(BlockConstant.RESPONSE_LATEST_BLOCK, JSON.toJSONString(newBlock));
				p2pService.broatcast(JSON.toJSONString(msg));
			} else {
				logger.warn("P2PService 为 null，无法广播新挖出的区块。");
			}
			return newBlock;
		} else {
			logger.error("挖矿成功但新区块 (哈希: {}) 未能添加到本地区块链 (可能是验证失败)。这些交易将保留在池中。", newBlockHash);
			// 如果区块添加失败，不应该从交易池中移除这些交易
			return null;
		}
	}
}