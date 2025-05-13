package com.bjut.blockchain.web.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.alibaba.fastjson.JSON;
import com.bjut.blockchain.web.model.Block;
import com.bjut.blockchain.web.model.Transaction;
import com.bjut.blockchain.web.util.BlockCache;
import com.bjut.blockchain.web.util.CryptoUtil;
import com.fasterxml.jackson.core.type.TypeReference;

/**
 * 区块链核心服务
 * 
 * @author Jared Jia
 *
 */
@Service
public class BlockService {
	// 使用线程安全的列表作为交易池
	private List<Transaction> transactionPool = new CopyOnWriteArrayList<>();
	private final ObjectMapper objectMapper = new ObjectMapper();

	@Autowired
	BlockCache blockCache;
	/**
	 * 创建创世区块
	 * @return
	 */
	public String createGenesisBlock() {
		Block genesisBlock = new Block();
		//设置创世区块高度为1
		genesisBlock.setIndex(1);
		genesisBlock.setTimestamp(System.currentTimeMillis());
		genesisBlock.setNonce(1);
		//封装业务数据
		List<Transaction> tsaList = new ArrayList<Transaction>();
		Transaction tsa = new Transaction();
		tsa.setId("1");
		tsa.setData("这是创世区块");
		tsaList.add(tsa);
		Transaction tsa2 = new Transaction();
		tsa2.setId("2");
		tsa.setData("区块链高度为：1");
		tsaList.add(tsa2);		
		genesisBlock.setTransactions(tsaList);
		//设置创世区块的hash值
		genesisBlock.setHash(calculateHash("",tsaList,1));
		//添加到已打包保存的业务数据集合中
		blockCache.getPackedTransactions().addAll(tsaList);
		//添加到区块链中
		blockCache.getBlockChain().add(genesisBlock);
		return JSON.toJSONString(genesisBlock);
	}
	
	/**
	 * 创建新区块
	 * @param nonce
	 * @param previousHash
	 * @param hash
	 * @param blockTxs
	 * @return
	 */
	public Block createNewBlock(int nonce, String previousHash, String hash, List<Transaction> blockTxs) {
		Block block = new Block();
		block.setIndex(blockCache.getBlockChain().size() + 1);
		//时间戳
		block.setTimestamp(System.currentTimeMillis());
		block.setTransactions(blockTxs);
		//工作量证明，计算正确hash值的次数
		block.setNonce(nonce);
		//上一区块的哈希
		block.setPreviousHash(previousHash);
		//当前区块的哈希
		block.setHash(hash);
		if (addBlock(block)) {
			return block;
		}
		return null;
	}

	/**
	 * 添加新区块到当前节点的区块链中
	 * 
	 * @param newBlock
	 */
	public boolean addBlock(Block newBlock) {
		//先对新区块的合法性进行校验
		if (isValidNewBlock(newBlock, blockCache.getLatestBlock())) {
			blockCache.getBlockChain().add(newBlock);
			// 新区块的业务数据需要加入到已打包的交易集合里去
			blockCache.getPackedTransactions().addAll(newBlock.getTransactions());
			return true;
		}
		return false;
	}
	
	/**
	 * 验证新区块是否有效
	 * 
	 * @param newBlock
	 * @param previousBlock
	 * @return
	 */
	public boolean isValidNewBlock(Block newBlock, Block previousBlock) {
		if (!previousBlock.getHash().equals(newBlock.getPreviousHash())) {
			System.out.println("新区块的前一个区块hash验证不通过");
			return false;
		} else {
			// 验证新区块hash值的正确性
			String hash = calculateHash(newBlock.getPreviousHash(), newBlock.getTransactions(), newBlock.getNonce());
			if (!hash.equals(newBlock.getHash())) {
				System.out.println("新区块的hash无效: " + hash + " " + newBlock.getHash());
				return false;
			}
			if (!isValidHash(newBlock.getHash())) {
				return false;
			}
		}

		return true;
	}
	
	/**
	 * 验证hash值是否满足系统条件
	 * 
	 * @param hash
	 * @return
	 */
	public boolean isValidHash(String hash) {
		return hash.startsWith("0000");
	}
	
	/**
	 * 验证整个区块链是否有效
	 * @param chain
	 * @return
	 */
	public boolean isValidChain(List<Block> chain) {
		Block block = null;
		Block lastBlock = chain.get(0);
		int currentIndex = 1;
		while (currentIndex < chain.size()) {
			block = chain.get(currentIndex);

			if (!isValidNewBlock(block, lastBlock)) {
				return false;
			}

			lastBlock = block;
			currentIndex++;
		}
		return true;
	}

	/**
	 * 替换本地区块链
	 * 
	 * @param newBlocks
	 */
	public void replaceChain(List<Block> newBlocks) {
		List<Block> localBlockChain = blockCache.getBlockChain();
		List<Transaction> localpackedTransactions = blockCache.getPackedTransactions();
		if (isValidChain(newBlocks) && newBlocks.size() > localBlockChain.size()) {
			localBlockChain = newBlocks;
			//替换已打包保存的业务数据集合
			localpackedTransactions.clear();
			localBlockChain.forEach(block -> {
				localpackedTransactions.addAll(block.getTransactions());
			});
			blockCache.setBlockChain(localBlockChain);
			blockCache.setPackedTransactions(localpackedTransactions);
			System.out.println("替换后的本节点区块链："+JSON.toJSONString(blockCache.getBlockChain()));
		} else {
			System.out.println("接收的区块链无效");
		}
	}

	/**
	 * 计算区块的hash
	 * 
	 * @param previousHash
	 * @param currentTransactions
	 * @param nonce
	 * @return
	 */
	public String calculateHash(String previousHash, List<Transaction> currentTransactions, int nonce) {
		return CryptoUtil.SHA256(previousHash + JSON.toJSONString(currentTransactions) + nonce);
	}

	/**
	 * 添加新的交易到交易池。
	 * 在实际应用中，这里应该包含对交易有效性的验证（如签名验证）。
	 *
	 * @param transaction 要添加的交易。
	 * @return 如果添加成功返回 true，否则返回 false。
	 */
	public boolean addTransaction(Transaction transaction) {
		// 1. 基本验证
		if (transaction == null || transaction.getId() == null /* || !isTransactionValid(transaction) */) {
			System.err.println("Invalid transaction received (null or missing ID). Ignoring.");
			return false;
		}
		// TODO: 在此添加更严格的交易验证逻辑 (例如验证签名, 检查格式等)


		// 2. 检查交易是否已在池中 (基于交易 ID)
		// 使用 stream API 提高效率
		if (transactionPool.stream().anyMatch(tx -> transaction.getId().equals(tx.getId()))) {
			System.out.println("Transaction " + transaction.getId() + " already in pool. Ignoring.");
			return false; // 已经存在，添加失败
		}

		// 3. 添加到交易池
		boolean added = transactionPool.add(transaction);
		if (added) {
			System.out.println("Transaction added to pool: " + transaction.getId() + " (Pool size: " + transactionPool.size() + ")");
			// 4. (可选) 广播新交易给网络
			// if (p2pService != null) {
			//     p2pService.broadcast(/* 构造交易消息, e.g., MessageUtil.newTransactionMessage(transaction) */);
			// }
		} else {
			System.err.println("Failed to add transaction " + transaction.getId() + " to the pool.");
		}
		return added;
	}

	/**
	 * 从区块链查找特定 DID 的最新锚定文档哈希。
	 * 遍历区块链，查找包含指定 DID 的 "DID_ANCHOR" 类型交易。
	 *
	 * @param did DID 字符串。
	 * @return 最新的锚定文档哈希，如果未找到则返回 null。
	 */
	public String findDidAnchorHash(String did) {
		if (did == null || did.isEmpty()) {
			return null;
		}
		List<Block> chain = blockCache.getBlockchain(); // 获取当前链
		String latestHash = null;
		long latestTimestamp = -1;

		// 从最新的区块开始向前查找效率更高
		for (int i = chain.size() - 1; i >= 0; i--) {
			Block block = chain.get(i);
			if (block.getTransactions() != null) {
				for (Transaction tx : block.getTransactions()) {
					// 检查交易数据是否包含 DID 锚定信息
					if (tx.getData() != null) {
						try {
							// 解析 JSON 数据到 Map
							Map<String, String> txData = objectMapper.readValue(tx.getData(), new TypeReference<Map<String, String>>() {});

							// 检查是否是 DID 锚定交易 ('type' 字段)
							// 并且 'did' 字段匹配
							// 并且包含 'documentHash' 字段
							if ("DID_ANCHOR".equals(txData.get("type")) &&
									did.equals(txData.get("did")) &&
									txData.containsKey("documentHash"))
							{
								// 如果找到多个锚定记录，取时间戳最新的一个
								if (block.getTimestamp() > latestTimestamp) {
									latestTimestamp = block.getTimestamp();
									latestHash = txData.get("documentHash");
									System.out.println("Found potential DID anchor for " + did + " in block " + block.getIndex() + " with hash " + latestHash);
								}
							}
						} catch (Exception e) {
							// JSON 解析错误或格式不匹配，忽略此交易数据
							// 可以选择性地记录日志:
							// System.err.println("Minor error parsing transaction data in block " + block.getIndex() + ": " + e.getMessage());
						}
					}
				}
			}
			// 如果已经找到了一个哈希，并且当前区块的时间戳远早于最新找到的时间戳，
			// 可以考虑提前终止循环以优化（假设时间戳大致递增）。
			// 但为了确保找到绝对最新的，遍历完整条链更可靠。
		}

		if (latestHash != null) {
			System.out.println("Found latest anchor hash for DID " + did + ": " + latestHash);
		} else {
			System.out.println("No anchor hash found for DID " + did + " in the blockchain.");
		}
		return latestHash; // 返回找到的最新哈希，或 null
	}
}
