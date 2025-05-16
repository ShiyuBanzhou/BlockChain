package com.bjut.blockchain.web.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "elections")
@Getter
@Setter
@NoArgsConstructor
public class ElectionEntity {

    @Id
    @Column(name = "election_id", length = 255, nullable = false, unique = true)
    private String electionId;

    @Column(name = "title", nullable = false)
    private String title;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "start_time", nullable = false)
    private long startTime;

    @Column(name = "end_time", nullable = false)
    private long endTime;

    @Column(name = "status", nullable = false)
    private String status;

    @Column(name = "creator_id", nullable = false)
    private String creatorId;

    @Column(name = "rules", columnDefinition = "TEXT")
    private String rules;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Long createdAt;

    @Column(name = "updated_at")
    private Long updatedAt;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = System.currentTimeMillis();
        }
        if (this.updatedAt == null) {
            this.updatedAt = System.currentTimeMillis();
        }
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = System.currentTimeMillis();
    }
} 