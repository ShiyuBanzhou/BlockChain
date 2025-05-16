package com.bjut.blockchain.web.model;

import java.io.Serializable;

/**
 * 候选人数据模型
 * 用于区块链投票系统中的候选人
 */
public class Candidate implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 候选人唯一ID
     */
    private String candidateId;

    /**
     * 候选人姓名
     */
    private String name;

    /**
     * 候选人简介
     */
    private String profile;

    /**
     * 关联的选举ID
     */
    private String electionId;

    /**
     * 候选人图片URL（可选）
     */
    private String imageUrl;

    /**
     * 附加信息（可选）
     */
    private String additionalInfo;

    // --- Getters and Setters ---

    public String getCandidateId() {
        return candidateId;
    }

    public void setCandidateId(String candidateId) {
        this.candidateId = candidateId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public String getElectionId() {
        return electionId;
    }

    public void setElectionId(String electionId) {
        this.electionId = electionId;
    }

    public String getImageUrl() {
        return imageUrl;
    }

    public void setImageUrl(String imageUrl) {
        this.imageUrl = imageUrl;
    }

    public String getAdditionalInfo() {
        return additionalInfo;
    }

    public void setAdditionalInfo(String additionalInfo) {
        this.additionalInfo = additionalInfo;
    }

    @Override
    public String toString() {
        return "Candidate{" +
                "candidateId='" + candidateId + '\'' +
                ", name='" + name + '\'' +
                ", profile='" + profile + '\'' +
                ", electionId='" + electionId + '\'' +
                ", imageUrl='" + imageUrl + '\'' +
                ", additionalInfo='" + additionalInfo + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Candidate candidate = (Candidate) o;
        return java.util.Objects.equals(candidateId, candidate.candidateId);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(candidateId);
    }
} 