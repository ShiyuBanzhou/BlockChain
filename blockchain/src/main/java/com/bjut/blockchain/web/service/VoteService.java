package com.bjut.blockchain.web.service;

import com.alibaba.fastjson.JSON;
import com.bjut.blockchain.web.entity.VoteEntity;
import com.bjut.blockchain.web.model.Transaction;
import com.bjut.blockchain.web.model.Vote;
import com.bjut.blockchain.web.repository.VoteRepository;
import com.bjut.blockchain.web.util.CommonUtil;
import com.bjut.blockchain.web.util.CryptoUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class VoteService {

    private static final Logger logger = LoggerFactory.getLogger(VoteService.class);

    private final VoteRepository voteRepository;
    private final BlockService blockService;
    private final ElectionService electionService;

    @Autowired
    public VoteService(VoteRepository voteRepository, BlockService blockService, ElectionService electionService) {
        this.voteRepository = voteRepository;
        this.blockService = blockService;
        this.electionService = electionService;
    }

    /**
     * 创建新投票并添加到区块链
     */
    @Transactional
    public Vote createVote(Vote vote, String voterPublicKey, String signature) {
        if (vote == null) {
            logger.error("尝试创建空投票");
            return null;
        }

        // 确保选举存在且正在进行中
        if (vote.getElectionId() == null || vote.getElectionId().isEmpty()) {
            logger.error("投票中缺少选举ID");
            return null;
        }

        // 检查选举状态
        String electionStatus = electionService.getElectionById(vote.getElectionId()).getStatus();
        if (!"进行中".equals(electionStatus)) {
            logger.error("选举 {} 不处于进行中状态，当前状态: {}", vote.getElectionId(), electionStatus);
            return null;
        }

        // 检查用户是否已经在此选举中投过票
        if (voteRepository.existsByElectionIdAndVoterId(vote.getElectionId(), vote.getVoterId())) {
            logger.error("用户 {} 已经在选举 {} 中投过票", vote.getVoterId(), vote.getElectionId());
            return null;
        }

        // 生成投票ID
        if (vote.getVoteId() == null || vote.getVoteId().isEmpty()) {
            vote.setVoteId(CommonUtil.generateUuid());
        }

        // 设置时间戳
        if (vote.getTimestamp() <= 0) {
            vote.setTimestamp(System.currentTimeMillis());
        }

        // 保存投票到数据库
        VoteEntity entity = convertToEntity(vote);
        entity = voteRepository.save(entity);

        // 创建区块链交易
        Transaction transaction = new Transaction();
        transaction.setId(CommonUtil.generateUuid());
        transaction.setTimestamp(vote.getTimestamp());
        transaction.setPublicKey(voterPublicKey);
        transaction.setSign(signature);

        // 将投票数据转为JSON字符串作为交易数据
        Map<String, Object> transactionData = new HashMap<>();
        transactionData.put("type", "vote");
        transactionData.put("voteId", vote.getVoteId());
        transactionData.put("electionId", vote.getElectionId());
        transactionData.put("voterId", vote.getVoterId());
        transactionData.put("candidateId", vote.getCandidateId());
        transactionData.put("timestamp", vote.getTimestamp());
        transaction.setData(JSON.toJSONString(transactionData));

        // 添加交易到区块链
        boolean addedToBlockchain = blockService.addTransaction(transaction);

        // 更新投票状态
        if (addedToBlockchain) {
            entity.setAddedToBlockchain(true);
            entity.setTransactionId(transaction.getId());
            voteRepository.save(entity);
        }

        return convertToModel(entity);
    }

    /**
     * 获取选举的投票统计
     */
    @Transactional(readOnly = true)
    public Map<String, Long> getVoteCountsByElection(String electionId) {
        if (electionId == null || electionId.isEmpty()) {
            return Collections.emptyMap();
        }

        List<Object[]> results = voteRepository.countVotesByCandidateForElection(electionId);
        Map<String, Long> voteCounts = new HashMap<>();

        for (Object[] result : results) {
            String candidateId = (String) result[0];
            Long count = ((Number) result[1]).longValue();
            voteCounts.put(candidateId, count);
        }

        return voteCounts;
    }

    /**
     * 获取选举的所有投票
     */
    @Transactional(readOnly = true)
    public List<Vote> getVotesByElection(String electionId) {
        if (electionId == null || electionId.isEmpty()) {
            return Collections.emptyList();
        }

        List<VoteEntity> entities = voteRepository.findByElectionId(electionId);
        return entities.stream()
                .map(this::convertToModel)
                .collect(Collectors.toList());
    }

    /**
     * 获取用户的投票历史
     */
    @Transactional(readOnly = true)
    public List<Vote> getVotesByVoter(String voterId) {
        if (voterId == null || voterId.isEmpty()) {
            return Collections.emptyList();
        }

        List<VoteEntity> entities = voteRepository.findByVoterId(voterId);
        return entities.stream()
                .map(this::convertToModel)
                .collect(Collectors.toList());
    }

    /**
     * 验证区块链上的投票数据
     */
    public boolean verifyVote(Vote vote, String blockHash) {
        if (vote == null || blockHash == null || blockHash.isEmpty()) {
            return false;
        }

        // 这里可以实现通过区块哈希查找区块，并验证投票的完整性
        // 该功能需要访问区块链数据并进行加密验证

        return true; // 这里简化了实现
    }

    /**
     * 处理尚未添加到区块链的投票
     * 通常由定时任务调用
     */
    @Transactional
    public int processPendingVotes() {
        List<VoteEntity> pendingVotes = voteRepository.findByAddedToBlockchain(false);
        int processedCount = 0;

        for (VoteEntity entity : pendingVotes) {
            // 尝试重新创建交易
            Transaction transaction = new Transaction();
            transaction.setId(CommonUtil.generateUuid());
            transaction.setTimestamp(entity.getTimestamp());
            
            // 创建交易数据
            Map<String, Object> transactionData = new HashMap<>();
            transactionData.put("type", "vote");
            transactionData.put("voteId", entity.getVoteId());
            transactionData.put("electionId", entity.getElectionId());
            transactionData.put("voterId", entity.getVoterId());
            transactionData.put("candidateId", entity.getCandidateId());
            transactionData.put("timestamp", entity.getTimestamp());
            transaction.setData(JSON.toJSONString(transactionData));

            // 添加到区块链
            if (blockService.addTransaction(transaction)) {
                entity.setAddedToBlockchain(true);
                entity.setTransactionId(transaction.getId());
                voteRepository.save(entity);
                processedCount++;
            }
        }

        return processedCount;
    }

    // 辅助方法：实体转模型
    private Vote convertToModel(VoteEntity entity) {
        if (entity == null) return null;
        
        Vote model = new Vote();
        model.setVoteId(entity.getVoteId());
        model.setVoterId(entity.getVoterId());
        model.setCandidateId(entity.getCandidateId());
        model.setTimestamp(entity.getTimestamp());
        model.setElectionId(entity.getElectionId());
        model.setAdditionalInfo(entity.getAdditionalInfo());
        
        return model;
    }
    
    // 辅助方法：模型转实体
    private VoteEntity convertToEntity(Vote model) {
        if (model == null) return null;
        
        VoteEntity entity = new VoteEntity(
            model.getVoteId(),
            model.getVoterId(),
            model.getCandidateId(),
            model.getTimestamp(),
            model.getElectionId(),
            model.getAdditionalInfo()
        );
        
        return entity;
    }
} 