package com.bjut.blockchain.web.service;

import com.alibaba.fastjson.JSON;
import com.bjut.blockchain.web.entity.PendingTransactionEntity; // 引入待处理交易实体
import com.bjut.blockchain.web.model.Block;
import com.bjut.blockchain.web.model.Transaction; // 业务模型
import com.bjut.blockchain.web.repository.PendingTransactionRepository; // 引入待处理交易仓库
import com.bjut.blockchain.web.util.BlockCache;
import com.bjut.blockchain.web.util.CryptoUtil;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper; // 用于 findDidAnchorHash
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 区块链核心服务
 * - 创建和添加区块
 * - 验证区块和链的有效性
 * - 计算哈希
 * - 管理待处理交易池（通过数据库持久化）
 * - 查找DID锚定哈希
 */
@Service
public class BlockService {
	private static final Logger logger = LoggerFactory.getLogger(BlockService.class);

	private final PendingTransactionRepository pendingTransactionRepository; // 注入仓库
	private final BlockCache blockCache; // BlockCache 依赖
	private final ObjectMapper objectMapper; // 用于 findDidAnchorHash 中的JSON解析

	@Autowired
	public BlockService(PendingTransactionRepository pendingTransactionRepository,
						BlockCache blockCache,
						ObjectMapper objectMapper) {
		this.pendingTransactionRepository = pendingTransactionRepository;
		this.blockCache = blockCache;
		this.objectMapper = objectMapper;
	}

	/**
	 * 创建创世区块，并确保其哈希满足挖矿难度。
	 * @return JSON字符串表示的创世区块。
	 */
	@Transactional
	public String createGenesisBlock() {
		if (blockCache.getBlockChain() != null && !blockCache.getBlockChain().isEmpty()) {
			logger.info("创世区块已存在，不再重复创建。");
			return JSON.toJSONString(blockCache.getLatestBlock());
		}

		logger.info("正在创建创世区块 (难度: {})...", blockCache.getDifficulty());
		Block genesisBlock = new Block();
		genesisBlock.setIndex(1);
		genesisBlock.setTimestamp(System.currentTimeMillis());
		// genesisBlock.setNonce(1); // Nonce将通过挖矿确定

		List<Transaction> tsaList = new ArrayList<>();
		Transaction tsa = new Transaction();
		tsa.setId("1");
		tsa.setTimestamp(genesisBlock.getTimestamp());
		tsa.setData("这是创世区块");
		tsaList.add(tsa);

		Transaction tsa2 = new Transaction();
		tsa2.setId("2");
		tsa2.setTimestamp(genesisBlock.getTimestamp());
		tsa2.setData("区块链高度为：1");
		tsaList.add(tsa2);
		genesisBlock.setTransactions(tsaList);
		genesisBlock.setPreviousHash("0");

		// 为创世区块进行挖矿以满足难度要求
		int nonce = 0;
		String hash;
		long startTime = System.currentTimeMillis();
		logger.info("开始为创世区块挖矿...");
		while (true) {
			hash = calculateHash(genesisBlock.getPreviousHash(), tsaList, nonce);
			if (isValidHash(hash)) {
				genesisBlock.setNonce(nonce);
				genesisBlock.setHash(hash);
				long timeTaken = System.currentTimeMillis() - startTime;
				logger.info("创世区块挖矿成功！Nonce: {}, Hash: {}, 耗时: {} ms", nonce, hash, timeTaken);
				break;
			}
			nonce++;
			if (nonce % 100000 == 0) { // 每10万次打印一次进度
				logger.debug("创世区块挖矿进行中... {} 次尝试", nonce);
			}
		}
		// --- 挖矿结束 ---

		if (blockCache.getPackedTransactions() != null) {
			blockCache.getPackedTransactions().addAll(tsaList);
		} else {
			logger.warn("BlockCache中的packedTransactions列表为null，无法添加创世区块交易。");
		}

		if (blockCache.getBlockChain() != null) {
			blockCache.getBlockChain().add(genesisBlock);
		} else {
			logger.warn("BlockCache中的blockChain列表为null，无法添加创世区块。");
		}

		logger.info("创世区块创建成功: Hash={}", genesisBlock.getHash());
		return JSON.toJSONString(genesisBlock);
	}

	/**
	 * 创建新区块模型对象 (尚未添加到链)。
	 * @param nonce 工作量证明计数器。
	 * @param previousHash 前一个区块的哈希。
	 * @param hash 当前区块的哈希。
	 * @param blockTxs 当前区块包含的交易列表。
	 * @return 创建的Block对象。
	 */
	public Block createNewBlock(int nonce, String previousHash, String hash, List<Transaction> blockTxs) {
		Block block = new Block();
		int currentIndex = 1;
		Block latestBlock = blockCache.getLatestBlock();
		if (latestBlock != null) {
			currentIndex = latestBlock.getIndex() + 1;
		} else if (blockCache.getBlockChain() != null && !blockCache.getBlockChain().isEmpty()){
			logger.warn("BlockCache.getLatestBlock() 返回null，但区块链非空。索引计算可能不准确。");
			currentIndex = blockCache.getBlockChain().size() + 1;
		}

		block.setIndex(currentIndex);
		block.setTimestamp(System.currentTimeMillis());
		block.setTransactions(blockTxs);
		block.setNonce(nonce);
		block.setPreviousHash(previousHash);
		block.setHash(hash);
		return block;
	}

	/**
	 * 添加新区块到当前节点的区块链中 (在BlockCache中)。
	 * @param newBlock 要添加的新区块。
	 * @return 如果添加成功（区块有效）返回 true，否则返回 false。
	 */
	public boolean addBlock(Block newBlock) {
		Block latestBlock = blockCache.getLatestBlock();
		// 创世块的特殊处理：如果链为空，且新块是索引1，则直接尝试添加
		if (latestBlock == null && newBlock.getIndex() == 1) {
			if (isValidNewBlock(newBlock, null)) { // 创世块的前一个块为null
				blockCache.getBlockChain().add(newBlock);
				if (newBlock.getTransactions() != null) {
					blockCache.getPackedTransactions().addAll(newBlock.getTransactions());
				}
				logger.info("创世区块 (索引: {}) 已添加到BlockCache。", newBlock.getIndex());
				return true;
			} else {
				logger.warn("尝试添加的创世区块 (索引: {}) 无效。", newBlock.getIndex());
				return false;
			}
		}
		// 非创世块的添加逻辑
		if (latestBlock == null && newBlock.getIndex() != 1) {
			logger.warn("尝试向空链（或无有效最新区块）中添加非初始区块，索引：{}", newBlock.getIndex());
		}

		if (isValidNewBlock(newBlock, latestBlock)) {
			blockCache.getBlockChain().add(newBlock);
			if (newBlock.getTransactions() != null) {
				blockCache.getPackedTransactions().addAll(newBlock.getTransactions());
			}
			logger.info("新区块 (索引: {}) 已添加到BlockCache。", newBlock.getIndex());
			return true;
		}
		logger.warn("添加新区块 (索引: {}) 失败，区块无效。", newBlock.getIndex());
		return false;
	}

	/**
	 * 验证新区块是否有效。
	 * @param newBlock 要验证的新区块。
	 * @param previousBlock 前一个区块 (如果newBlock不是创世区块，则为null)。
	 * @return 如果有效返回true，否则返回false。
	 */
	public boolean isValidNewBlock(Block newBlock, Block previousBlock) {
		if (newBlock == null) {
			logger.warn("验证区块失败：新区块为null。");
			return false;
		}

		// 验证哈希是否满足挖矿难度 (这个检查应该最先进行，因为它是PoW的核心)
		if (!isValidHash(newBlock.getHash())) {
			logger.warn("新区块的哈希 {} 不满足挖矿难度要求 (难度: {}).", newBlock.getHash(), blockCache.getDifficulty());
			return false;
		}

		// 验证新区块自身的哈希计算是否正确
		String calculatedHash = calculateHash(newBlock.getPreviousHash(), newBlock.getTransactions(), newBlock.getNonce());
		if (newBlock.getHash() == null || !newBlock.getHash().equals(calculatedHash)) {
			logger.warn("新区块的哈希值计算不正确: 计算值 {}, 区块内记录值 {}", calculatedHash, newBlock.getHash());
			return false;
		}

		// 对于创世区块（或链上的第一个区块），previousBlock可能为null
		if (previousBlock != null) { // 验证与前一个区块的连接 (非创世块)
			if (newBlock.getIndex() != previousBlock.getIndex() + 1) {
				logger.warn("新区块索引无效: 期望 {}, 实际 {}", previousBlock.getIndex() + 1, newBlock.getIndex());
				return false;
			}
			if (newBlock.getPreviousHash() == null || !newBlock.getPreviousHash().equals(previousBlock.getHash())) {
				logger.warn("新区块的前一个区块哈希验证不通过: 期望 {}, 实际 {}", previousBlock.getHash(), newBlock.getPreviousHash());
				return false;
			}
		} else { // 如果是链上的第一个块 (previousBlock is null)
			if (newBlock.getIndex() != 1) {
				logger.warn("链上第一个区块 (previousBlock为null时) 的索引 {} 不为1。", newBlock.getIndex());
				return false;
			}
			// 创世块的 previousHash 应该是 "0" 或一个特定值
			if (!"0".equals(newBlock.getPreviousHash())) {
				logger.warn("创世区块的 previousHash '{}' 不为 '0'。", newBlock.getPreviousHash());
				return false;
			}
		}
		return true;
	}

	/**
	 * 验证哈希值是否满足系统挖矿难度条件。
	 * @param hash 要验证的哈希字符串。
	 * @return 如果满足条件返回true。
	 */
	public boolean isValidHash(String hash) {
		if (hash == null) return false;
		String prefix = new String(new char[blockCache.getDifficulty()]).replace('\0', '0');
		return hash.startsWith(prefix);
	}

	/**
	 * 验证整条区块链是否有效。
	 * @param chainToValidate 要验证的区块链。
	 * @return 如果有效返回true。
	 */
	public boolean isValidChain(List<Block> chainToValidate) {
		if (chainToValidate == null || chainToValidate.isEmpty()) {
			logger.warn("尝试验证空或null的区块链。");
			return false;
		}

		// 验证第一个区块 (通常是创世区块)
		Block firstBlock = chainToValidate.get(0);
		if (!isValidNewBlock(firstBlock, null)) { // 创世块的 previousBlock 是 null
			logger.warn("链中的第一个区块 (索引 {}) 自身无效。", firstBlock.getIndex());
			return false;
		}

		// 验证后续区块
		for (int i = 1; i < chainToValidate.size(); i++) {
			Block currentBlock = chainToValidate.get(i);
			Block previousBlock = chainToValidate.get(i - 1);
			if (!isValidNewBlock(currentBlock, previousBlock)) {
				logger.warn("区块链在索引 {} 处无效 (当前区块哈希 {})。", currentBlock.getIndex(), currentBlock.getHash());
				return false;
			}
		}
		logger.debug("区块链验证通过 (包含 {} 个区块)。", chainToValidate.size());
		return true;
	}

	/**
	 * 如果接收到的区块链比当前节点的长且有效，则替换本地区块链。
	 * @param newBlocks 接收到的新区块链。
	 */
	@Transactional
	public void replaceChain(List<Block> newBlocks) {
		List<Block> localBlockChain = blockCache.getBlockChain();

		if (isValidChain(newBlocks) && newBlocks.size() > localBlockChain.size()) {
			logger.info("接收到的区块链有效且更长。将替换本地区块链 (本地长度: {}, 接收长度: {})。",
					localBlockChain.size(), newBlocks.size());
			blockCache.setBlockChain(new ArrayList<>(newBlocks));

			List<Transaction> newPackedTransactions = new ArrayList<>();
			newBlocks.forEach(block -> {
				if (block.getTransactions() != null) {
					newPackedTransactions.addAll(block.getTransactions());
				}
			});
			blockCache.setPackedTransactions(newPackedTransactions);
			logger.info("本地区块链已成功替换。");
		} else {
			logger.warn("接收到的区块链无效或不够长，不替换本地区块链。");
		}
	}

	/**
	 * 计算给定参数的区块哈希值 (SHA256)。
	 * @param previousHash 前一个区块的哈希。
	 * @param currentTransactions 当前区块的交易列表。
	 * @param nonce 工作量证明计数器。
	 * @return 计算得到的哈希字符串。
	 */
	public String calculateHash(String previousHash, List<Transaction> currentTransactions, int nonce) {
		String prevHashForCalc = (previousHash == null) ? "0" : previousHash;
		String transactionsJson = JSON.toJSONString(currentTransactions);
		return CryptoUtil.SHA256(prevHashForCalc + transactionsJson + nonce);
	}

	/**
	 * 添加新的交易到待处理交易池 (数据库)。
	 * @param transaction 要添加的交易模型对象。
	 * @return 如果添加成功返回 true，否则返回 false。
	 */
	@Transactional
	public boolean addTransaction(Transaction transaction) {
		if (transaction == null || transaction.getId() == null || transaction.getId().isEmpty()) {
			logger.warn("尝试添加无效的交易 (ID为空或对象为null)。");
			return false;
		}
		if (pendingTransactionRepository.existsById(transaction.getId())) {
			logger.info("交易 '{}' 已存在于待处理池中，将被忽略。", transaction.getId());
			return false;
		}

		PendingTransactionEntity entity = new PendingTransactionEntity(
				transaction.getId(),
				transaction.getPublicKey(),
				transaction.getSign(),
				transaction.getTimestamp(),
				transaction.getData()
		);

		try {
			pendingTransactionRepository.save(entity);
			logger.info("交易 '{}' 已成功添加到待处理池 (数据库)。当前池大小: {}", transaction.getId(), pendingTransactionRepository.count());
			return true;
		} catch (Exception e) {
			logger.error("添加交易 '{}' 到待处理池时发生数据库错误: {}", transaction.getId(), e.getMessage(), e);
			return false;
		}
	}

	/**
	 * 从待处理交易池 (数据库) 中获取所有交易，按加入时间排序。
	 * @return 交易模型对象的列表。
	 */
	@Transactional(readOnly = true)
	public List<Transaction> getTransactionPool() {
		List<PendingTransactionEntity> entities = pendingTransactionRepository.findAllByOrderByAddedToPoolAtAsc();
		if (entities.isEmpty()) {
			return new ArrayList<>();
		}
		return entities.stream().map(entity -> {
			Transaction tx = new Transaction();
			tx.setId(entity.getId());
			tx.setPublicKey(entity.getPublicKey());
			tx.setSign(entity.getSign());
			tx.setTimestamp(entity.getTimestamp());
			tx.setData(entity.getData());
			return tx;
		}).collect(Collectors.toList());
	}

	/**
	 * (重要) 从待处理交易池 (数据库) 中移除指定的交易列表。
	 * @param transactionsToRemove 要移除的交易列表 (模型对象)
	 */
	@Transactional
	public void removeTransactionsFromPool(List<Transaction> transactionsToRemove) {
		if (transactionsToRemove == null || transactionsToRemove.isEmpty()) {
			logger.debug("没有需要从交易池中移除的交易。");
			return;
		}
		List<String> transactionIdsToRemove = transactionsToRemove.stream()
				.map(Transaction::getId)
				.filter(id -> id != null && !id.isEmpty())
				.collect(Collectors.toList());
		if (transactionIdsToRemove.isEmpty()){
			logger.debug("要移除的交易ID列表为空或所有ID均无效。");
			return;
		}
		try {
			pendingTransactionRepository.deleteAllByIdIn(transactionIdsToRemove);
			logger.info("成功从待处理交易池中移除了 {} 个已打包的交易 (ID: {})。",
					transactionIdsToRemove.size(), transactionIdsToRemove);
		} catch (Exception e) {
			logger.error("从待处理交易池移除已打包交易时出错: {}", e.getMessage(), e);
		}
	}

	/**
	 * 从区块链查找特定 DID 的最新锚定文档哈希。
	 * 此方法查询的是已打包在区块中的交易。
	 * @param did DID 字符串。
	 * @return 最新的锚定文档哈希，如果未找到则返回 null。
	 */
	public String findDidAnchorHash(String did) {
		if (did == null || did.isEmpty()) {
			return null;
		}
		List<Block> chain = blockCache.getBlockchain(); // getBlockChain() is the correct method
		String latestHash = null;
		long latestTimestamp = -1L;

		for (int i = chain.size() - 1; i >= 0; i--) {
			Block block = chain.get(i);
			if (block.getTransactions() != null) {
				for (Transaction tx : block.getTransactions()) {
					if (tx.getData() != null) {
						try {
							Map<String, String> txData = objectMapper.readValue(tx.getData(), new TypeReference<Map<String, String>>() {});
							if ("DID_ANCHOR".equals(txData.get("type")) &&
									did.equals(txData.get("did")) &&
									txData.containsKey("documentHash")) {
								if (block.getTimestamp() > latestTimestamp) {
									latestTimestamp = block.getTimestamp();
									latestHash = txData.get("documentHash");
								}
							}
						} catch (Exception e) {
							logger.warn("解析交易数据时发生错误，区块索引 {}，交易ID {}: {}", block.getIndex(), tx.getId(), e.getMessage());
						}
					}
				}
			}
		}

		if (latestHash != null) {
			logger.debug("为DID '{}' 找到的最新锚定哈希: {}", did, latestHash);
		} else {
			logger.debug("未在区块链中为DID '{}' 找到锚定哈希。", did);
		}
		return latestHash;
	}
}
