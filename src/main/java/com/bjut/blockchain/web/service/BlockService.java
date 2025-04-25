package com.bjut.blockchain.web.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.alibaba.fastjson.JSON;
import com.bjut.blockchain.web.model.Block;
import com.bjut.blockchain.web.model.Transaction;
import com.bjut.blockchain.web.util.BlockCache;
import com.bjut.blockchain.web.util.CryptoUtil;

/**
 * 区块链核心服务
 * 
 * @author Jared Jia
 *
 */
@Service
public class BlockService {

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
		tsa.setBusinessInfo("这是创世区块");
		tsaList.add(tsa);
		Transaction tsa2 = new Transaction();
		tsa2.setId("2");
		tsa2.setBusinessInfo("区块链高度为：1");
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

}
