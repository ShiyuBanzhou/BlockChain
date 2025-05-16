package com.bjut.blockchain.web.controller;

import com.alibaba.fastjson.JSON;
import com.bjut.blockchain.web.model.Vote;
import com.bjut.blockchain.web.service.VoteService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 区块链投票系统 - 投票控制器
 */
@RestController
@RequestMapping("/api/votes")
public class VoteController {

    private static final Logger logger = LoggerFactory.getLogger(VoteController.class);

    private final VoteService voteService;

    @Autowired
    public VoteController(VoteService voteService) {
        this.voteService = voteService;
    }

    /**
     * 提交投票
     * 路径: POST /api/votes
     */
    @PostMapping
    public ResponseEntity<?> createVote(@RequestBody Map<String, Object> voteRequest) {
        try {
            // 从请求中提取数据
            Vote vote = new Vote();
            vote.setVoterId((String) voteRequest.get("voterId"));
            vote.setCandidateId((String) voteRequest.get("candidateId"));
            vote.setElectionId((String) voteRequest.get("electionId"));
            vote.setAdditionalInfo((String) voteRequest.get("additionalInfo"));
            
            String voterPublicKey = (String) voteRequest.get("publicKey");
            String signature = (String) voteRequest.get("signature");

            // 记录投票请求
            logger.info("接收到投票请求：选民={}, 候选人={}, 选举={}", 
                    vote.getVoterId(), vote.getCandidateId(), vote.getElectionId());

            // 创建投票并添加到区块链
            Vote createdVote = voteService.createVote(vote, voterPublicKey, signature);
            
            if (createdVote != null) {
                return ResponseEntity.ok(createdVote);
            } else {
                return ResponseEntity.badRequest().body("投票失败，可能已经投过票或选举未开始");
            }
        } catch (Exception e) {
            logger.error("处理投票时发生错误: ", e);
            return ResponseEntity.badRequest().body("投票时发生错误: " + e.getMessage());
        }
    }

    /**
     * 获取选举的投票统计
     * 路径: GET /api/votes/count/{electionId}
     */
    @GetMapping("/count/{electionId}")
    public ResponseEntity<?> getVoteCountsByElection(@PathVariable String electionId) {
        try {
            Map<String, Long> voteCounts = voteService.getVoteCountsByElection(electionId);
            return ResponseEntity.ok(voteCounts);
        } catch (Exception e) {
            logger.error("获取投票统计时发生错误: ", e);
            return ResponseEntity.badRequest().body("获取投票统计时发生错误: " + e.getMessage());
        }
    }

    /**
     * 获取选举的所有投票
     * 路径: GET /api/votes/election/{electionId}
     */
    @GetMapping("/election/{electionId}")
    public ResponseEntity<List<Vote>> getVotesByElection(@PathVariable String electionId) {
        try {
            List<Vote> votes = voteService.getVotesByElection(electionId);
            return ResponseEntity.ok(votes);
        } catch (Exception e) {
            logger.error("获取选举投票时发生错误: ", e);
            return ResponseEntity.badRequest().body(null);
        }
    }

    /**
     * 获取用户的投票历史
     * 路径: GET /api/votes/voter/{voterId}
     */
    @GetMapping("/voter/{voterId}")
    public ResponseEntity<List<Vote>> getVotesByVoter(@PathVariable String voterId) {
        try {
            List<Vote> votes = voteService.getVotesByVoter(voterId);
            return ResponseEntity.ok(votes);
        } catch (Exception e) {
            logger.error("获取用户投票历史时发生错误: ", e);
            return ResponseEntity.badRequest().body(null);
        }
    }

    /**
     * 手动处理待处理的投票
     * 路径: POST /api/votes/process-pending
     */
    @PostMapping("/process-pending")
    public ResponseEntity<?> processPendingVotes() {
        try {
            int processedCount = voteService.processPendingVotes();
            
            Map<String, Object> response = new HashMap<>();
            response.put("processedCount", processedCount);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("处理待处理投票时发生错误: ", e);
            return ResponseEntity.badRequest().body("处理待处理投票时发生错误: " + e.getMessage());
        }
    }
} 