package com.bjut.blockchain.web.service;

import com.bjut.blockchain.web.entity.CandidateEntity;
import com.bjut.blockchain.web.entity.ElectionEntity;
import com.bjut.blockchain.web.model.Candidate;
import com.bjut.blockchain.web.model.Election;
import com.bjut.blockchain.web.repository.CandidateRepository;
import com.bjut.blockchain.web.repository.ElectionRepository;
import com.bjut.blockchain.web.util.CommonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class ElectionService {

    private static final Logger logger = LoggerFactory.getLogger(ElectionService.class);

    private final ElectionRepository electionRepository;
    private final CandidateRepository candidateRepository;

    @Autowired
    public ElectionService(ElectionRepository electionRepository, CandidateRepository candidateRepository) {
        this.electionRepository = electionRepository;
        this.candidateRepository = candidateRepository;
    }

    /**
     * 创建新选举
     */
    @Transactional
    public Election createElection(Election election) {
        if (election == null) {
            logger.error("尝试创建空选举");
            return null;
        }

        // 生成选举ID
        if (election.getElectionId() == null || election.getElectionId().isEmpty()) {
            election.setElectionId(CommonUtil.generateUuid());
        }

        // 更新状态
        election.updateStatus();

        // 转换为实体并保存
        ElectionEntity entity = convertToEntity(election);
        ElectionEntity savedEntity = electionRepository.save(entity);

        // 如果有候选人，保存候选人信息
        if (election.getCandidates() != null && !election.getCandidates().isEmpty()) {
            final String electionId = savedEntity.getElectionId();
            List<CandidateEntity> candidateEntities = election.getCandidates().stream()
                    .map(candidate -> {
                        // 确保候选人ID和选举ID
                        if (candidate.getCandidateId() == null || candidate.getCandidateId().isEmpty()) {
                            candidate.setCandidateId(CommonUtil.generateUuid());
                        }
                        candidate.setElectionId(electionId);
                        return convertToEntity(candidate);
                    })
                    .collect(Collectors.toList());
            candidateRepository.saveAll(candidateEntities);
        }

        // 返回创建的选举（包含ID）
        return convertToModel(savedEntity);
    }

    /**
     * 获取选举列表
     */
    @Transactional(readOnly = true)
    public List<Election> getAllElections() {
        List<ElectionEntity> entities = electionRepository.findAllByOrderByCreatedAtDesc();
        return entities.stream()
                .map(this::convertToModelWithCandidates)
                .collect(Collectors.toList());
    }

    /**
     * 根据ID获取选举
     */
    @Transactional(readOnly = true)
    public Election getElectionById(String electionId) {
        if (electionId == null || electionId.isEmpty()) {
            return null;
        }

        Optional<ElectionEntity> optionalEntity = electionRepository.findById(electionId);
        if (optionalEntity.isPresent()) {
            return convertToModelWithCandidates(optionalEntity.get());
        }
        return null;
    }

    /**
     * 更新选举信息
     */
    @Transactional
    public Election updateElection(Election election) {
        if (election == null || election.getElectionId() == null || election.getElectionId().isEmpty()) {
            logger.error("尝试更新无效的选举");
            return null;
        }

        // 检查选举是否存在
        Optional<ElectionEntity> optionalExisting = electionRepository.findById(election.getElectionId());
        if (!optionalExisting.isPresent()) {
            logger.error("找不到ID为{}的选举", election.getElectionId());
            return null;
        }

        // 更新选举状态
        election.updateStatus();

        // 更新选举实体
        ElectionEntity entity = convertToEntity(election);
        ElectionEntity savedEntity = electionRepository.save(entity);

        // 如果有候选人列表，则更新候选人
        if (election.getCandidates() != null) {
            // 先删除现有的候选人
            List<CandidateEntity> existingCandidates = candidateRepository.findByElectionId(election.getElectionId());
            candidateRepository.deleteAll(existingCandidates);

            // 保存新的候选人列表
            final String electionId = savedEntity.getElectionId();
            List<CandidateEntity> newCandidates = election.getCandidates().stream()
                    .map(candidate -> {
                        if (candidate.getCandidateId() == null || candidate.getCandidateId().isEmpty()) {
                            candidate.setCandidateId(CommonUtil.generateUuid());
                        }
                        candidate.setElectionId(electionId);
                        return convertToEntity(candidate);
                    })
                    .collect(Collectors.toList());
            candidateRepository.saveAll(newCandidates);
        }

        return convertToModelWithCandidates(savedEntity);
    }

    /**
     * 删除选举
     */
    @Transactional
    public boolean deleteElection(String electionId) {
        if (electionId == null || electionId.isEmpty()) {
            return false;
        }

        // 先删除关联的候选人
        List<CandidateEntity> candidates = candidateRepository.findByElectionId(electionId);
        candidateRepository.deleteAll(candidates);

        // 删除选举
        electionRepository.deleteById(electionId);
        return true;
    }

    /**
     * 获取正在进行中的选举
     */
    @Transactional(readOnly = true)
    public List<Election> getActiveElections() {
        // 先更新所有选举的状态
        updateAllElectionStatuses();
        
        List<ElectionEntity> entities = electionRepository.findByStatusOrderByStartTimeAsc("进行中");
        return entities.stream()
                .map(this::convertToModelWithCandidates)
                .collect(Collectors.toList());
    }

    /**
     * 更新所有选举状态
     */
    @Transactional
    public void updateAllElectionStatuses() {
        List<ElectionEntity> allElections = electionRepository.findAll();
        long currentTime = System.currentTimeMillis();
        
        for (ElectionEntity entity : allElections) {
            String oldStatus = entity.getStatus();
            String newStatus;
            
            if (currentTime < entity.getStartTime()) {
                newStatus = "未开始";
            } else if (currentTime >= entity.getStartTime() && currentTime <= entity.getEndTime()) {
                newStatus = "进行中";
            } else {
                newStatus = "已结束";
            }
            
            if (!oldStatus.equals(newStatus)) {
                entity.setStatus(newStatus);
                electionRepository.save(entity);
            }
        }
    }

    // 辅助方法：实体转模型
    private Election convertToModel(ElectionEntity entity) {
        if (entity == null) return null;
        
        Election model = new Election();
        model.setElectionId(entity.getElectionId());
        model.setTitle(entity.getTitle());
        model.setDescription(entity.getDescription());
        model.setStartTime(entity.getStartTime());
        model.setEndTime(entity.getEndTime());
        model.setStatus(entity.getStatus());
        model.setCreatorId(entity.getCreatorId());
        model.setRules(entity.getRules());
        
        return model;
    }
    
    // 辅助方法：实体转模型（包含候选人）
    private Election convertToModelWithCandidates(ElectionEntity entity) {
        Election model = convertToModel(entity);
        if (model == null) return null;
        
        // 获取选举关联的候选人
        List<CandidateEntity> candidateEntities = candidateRepository.findByElectionId(entity.getElectionId());
        List<Candidate> candidates = candidateEntities.stream()
                .map(this::convertToModel)
                .collect(Collectors.toList());
        
        model.setCandidates(candidates);
        return model;
    }
    
    // 辅助方法：模型转实体
    private ElectionEntity convertToEntity(Election model) {
        if (model == null) return null;
        
        ElectionEntity entity = new ElectionEntity();
        entity.setElectionId(model.getElectionId());
        entity.setTitle(model.getTitle());
        entity.setDescription(model.getDescription());
        entity.setStartTime(model.getStartTime());
        entity.setEndTime(model.getEndTime());
        entity.setStatus(model.getStatus());
        entity.setCreatorId(model.getCreatorId());
        entity.setRules(model.getRules());
        
        return entity;
    }
    
    // 辅助方法：候选人实体转模型
    private Candidate convertToModel(CandidateEntity entity) {
        if (entity == null) return null;
        
        Candidate model = new Candidate();
        model.setCandidateId(entity.getCandidateId());
        model.setName(entity.getName());
        model.setProfile(entity.getProfile());
        model.setElectionId(entity.getElectionId());
        model.setImageUrl(entity.getImageUrl());
        model.setAdditionalInfo(entity.getAdditionalInfo());
        
        return model;
    }
    
    // 辅助方法：候选人模型转实体
    private CandidateEntity convertToEntity(Candidate model) {
        if (model == null) return null;
        
        CandidateEntity entity = new CandidateEntity();
        entity.setCandidateId(model.getCandidateId());
        entity.setName(model.getName());
        entity.setProfile(model.getProfile());
        entity.setElectionId(model.getElectionId());
        entity.setImageUrl(model.getImageUrl());
        entity.setAdditionalInfo(model.getAdditionalInfo());
        
        return entity;
    }
} 