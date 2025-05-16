package com.bjut.blockchain.web.controller;

import com.alibaba.fastjson.JSON;
import com.bjut.blockchain.web.model.Election;
import com.bjut.blockchain.web.service.ElectionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 区块链投票系统 - 选举控制器
 */
@RestController
@RequestMapping("/api/elections")
public class ElectionController {

    private static final Logger logger = LoggerFactory.getLogger(ElectionController.class);

    private final ElectionService electionService;

    @Autowired
    public ElectionController(ElectionService electionService) {
        this.electionService = electionService;
    }

    /**
     * 创建新选举
     * 路径: POST /api/elections
     */
    @PostMapping
    public ResponseEntity<?> createElection(@RequestBody Election election) {
        try {
            logger.info("接收到创建选举请求: {}", election.getTitle());
            Election createdElection = electionService.createElection(election);
            if (createdElection != null) {
                return ResponseEntity.ok(createdElection);
            } else {
                return ResponseEntity.badRequest().body("创建选举失败");
            }
        } catch (Exception e) {
            logger.error("创建选举时发生错误: ", e);
            return ResponseEntity.badRequest().body("创建选举时发生错误: " + e.getMessage());
        }
    }

    /**
     * 获取所有选举
     * 路径: GET /api/elections
     */
    @GetMapping
    public ResponseEntity<List<Election>> getAllElections() {
        try {
            List<Election> elections = electionService.getAllElections();
            return ResponseEntity.ok(elections);
        } catch (Exception e) {
            logger.error("获取选举列表时发生错误: ", e);
            return ResponseEntity.badRequest().body(null);
        }
    }

    /**
     * 获取单个选举详情
     * 路径: GET /api/elections/{electionId}
     */
    @GetMapping("/{electionId}")
    public ResponseEntity<?> getElectionById(@PathVariable String electionId) {
        try {
            Election election = electionService.getElectionById(electionId);
            if (election != null) {
                return ResponseEntity.ok(election);
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            logger.error("获取选举详情时发生错误: ", e);
            return ResponseEntity.badRequest().body("获取选举详情时发生错误: " + e.getMessage());
        }
    }

    /**
     * 更新选举信息
     * 路径: PUT /api/elections/{electionId}
     */
    @PutMapping("/{electionId}")
    public ResponseEntity<?> updateElection(@PathVariable String electionId, @RequestBody Election election) {
        try {
            if (!electionId.equals(election.getElectionId())) {
                return ResponseEntity.badRequest().body("URL中的选举ID与请求体中的不匹配");
            }
            
            Election updatedElection = electionService.updateElection(election);
            if (updatedElection != null) {
                return ResponseEntity.ok(updatedElection);
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            logger.error("更新选举时发生错误: ", e);
            return ResponseEntity.badRequest().body("更新选举时发生错误: " + e.getMessage());
        }
    }

    /**
     * 删除选举
     * 路径: DELETE /api/elections/{electionId}
     */
    @DeleteMapping("/{electionId}")
    public ResponseEntity<?> deleteElection(@PathVariable String electionId) {
        try {
            boolean deleted = electionService.deleteElection(electionId);
            if (deleted) {
                return ResponseEntity.ok().body("选举已成功删除");
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            logger.error("删除选举时发生错误: ", e);
            return ResponseEntity.badRequest().body("删除选举时发生错误: " + e.getMessage());
        }
    }

    /**
     * 获取进行中的选举
     * 路径: GET /api/elections/active
     */
    @GetMapping("/active")
    public ResponseEntity<List<Election>> getActiveElections() {
        try {
            List<Election> activeElections = electionService.getActiveElections();
            return ResponseEntity.ok(activeElections);
        } catch (Exception e) {
            logger.error("获取进行中的选举时发生错误: ", e);
            return ResponseEntity.badRequest().body(null);
        }
    }
} 