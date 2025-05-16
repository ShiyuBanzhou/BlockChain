package com.bjut.blockchain.web.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "candidates")
@Getter
@Setter
@NoArgsConstructor
public class CandidateEntity {

    @Id
    @Column(name = "candidate_id", length = 255, nullable = false, unique = true)
    private String candidateId;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "profile", columnDefinition = "TEXT")
    private String profile;

    @Column(name = "election_id", nullable = false)
    private String electionId;

    @Column(name = "image_url")
    private String imageUrl;

    @Column(name = "additional_info", columnDefinition = "TEXT")
    private String additionalInfo;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Long createdAt;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = System.currentTimeMillis();
        }
    }
} 