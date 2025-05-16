package com.bjut.blockchain.web.model;

import java.io.Serializable;
import java.util.List;

/**
 * 选举数据模型
 * 用于区块链投票系统中的选举活动
 */
public class Election implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 选举唯一ID
     */
    private String electionId;

    /**
     * 选举标题
     */
    private String title;

    /**
     * 选举描述
     */
    private String description;

    /**
     * 选举开始时间
     */
    private long startTime;

    /**
     * 选举结束时间
     */
    private long endTime;

    /**
     * 候选人列表
     */
    private List<Candidate> candidates;

    /**
     * 选举状态：未开始、进行中、已结束
     */
    private String status;

    /**
     * 创建者ID
     */
    private String creatorId;

    /**
     * 选举规则 (以JSON字符串存储)
     */
    private String rules;

    // --- Getters and Setters ---

    public String getElectionId() {
        return electionId;
    }

    public void setElectionId(String electionId) {
        this.electionId = electionId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public long getStartTime() {
        return startTime;
    }

    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }

    public long getEndTime() {
        return endTime;
    }

    public void setEndTime(long endTime) {
        this.endTime = endTime;
    }

    public List<Candidate> getCandidates() {
        return candidates;
    }

    public void setCandidates(List<Candidate> candidates) {
        this.candidates = candidates;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getCreatorId() {
        return creatorId;
    }

    public void setCreatorId(String creatorId) {
        this.creatorId = creatorId;
    }

    public String getRules() {
        return rules;
    }

    public void setRules(String rules) {
        this.rules = rules;
    }

    /**
     * 根据当前时间更新选举状态
     */
    public void updateStatus() {
        long currentTime = System.currentTimeMillis();
        
        if (currentTime < startTime) {
            status = "未开始";
        } else if (currentTime >= startTime && currentTime <= endTime) {
            status = "进行中";
        } else {
            status = "已结束";
        }
    }

    @Override
    public String toString() {
        return "Election{" +
                "electionId='" + electionId + '\'' +
                ", title='" + title + '\'' +
                ", description='" + description + '\'' +
                ", startTime=" + startTime +
                ", endTime=" + endTime +
                ", candidates=" + candidates +
                ", status='" + status + '\'' +
                ", creatorId='" + creatorId + '\'' +
                ", rules='" + rules + '\'' +
                '}';
    }
} 