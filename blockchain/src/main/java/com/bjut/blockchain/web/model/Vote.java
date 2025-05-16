package com.bjut.blockchain.web.model;

import java.io.Serializable;

/**
 * 投票数据模型
 * 用于区块链投票系统中的投票记录
 */
public class Vote implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 投票唯一ID
     */
    private String voteId;

    /**
     * 投票人ID（DID或用户标识）
     */
    private String voterId;

    /**
     * 投票对象/候选人ID
     */
    private String candidateId;

    /**
     * 投票时间戳
     */
    private long timestamp;

    /**
     * 投票活动/选举ID
     */
    private String electionId;

    /**
     * 附加信息（可选）
     */
    private String additionalInfo;

    // --- Getters and Setters ---

    public String getVoteId() {
        return voteId;
    }

    public void setVoteId(String voteId) {
        this.voteId = voteId;
    }

    public String getVoterId() {
        return voterId;
    }

    public void setVoterId(String voterId) {
        this.voterId = voterId;
    }

    public String getCandidateId() {
        return candidateId;
    }

    public void setCandidateId(String candidateId) {
        this.candidateId = candidateId;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getElectionId() {
        return electionId;
    }

    public void setElectionId(String electionId) {
        this.electionId = electionId;
    }

    public String getAdditionalInfo() {
        return additionalInfo;
    }

    public void setAdditionalInfo(String additionalInfo) {
        this.additionalInfo = additionalInfo;
    }

    @Override
    public String toString() {
        return "Vote{" +
                "voteId='" + voteId + '\'' +
                ", voterId='" + voterId + '\'' +
                ", candidateId='" + candidateId + '\'' +
                ", timestamp=" + timestamp +
                ", electionId='" + electionId + '\'' +
                ", additionalInfo='" + additionalInfo + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Vote vote = (Vote) o;
        return java.util.Objects.equals(voteId, vote.voteId);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(voteId);
    }
} 