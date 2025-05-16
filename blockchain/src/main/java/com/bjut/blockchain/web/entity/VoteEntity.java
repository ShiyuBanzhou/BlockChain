package com.bjut.blockchain.web.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "votes")
@Getter
@Setter
@NoArgsConstructor
public class VoteEntity {

    @Id
    @Column(name = "vote_id", length = 255, nullable = false, unique = true)
    private String voteId;

    @Column(name = "voter_id", nullable = false)
    private String voterId;

    @Column(name = "candidate_id", nullable = false)
    private String candidateId;

    @Column(name = "timestamp", nullable = false)
    private long timestamp;

    @Column(name = "election_id", nullable = false)
    private String electionId;

    @Column(name = "additional_info", columnDefinition = "TEXT")
    private String additionalInfo;

    @Column(name = "added_to_blockchain")
    private boolean addedToBlockchain = false;

    @Column(name = "transaction_id")
    private String transactionId;

    @Column(name = "block_hash")
    private String blockHash;

    public VoteEntity(String voteId, String voterId, String candidateId, long timestamp, String electionId, String additionalInfo) {
        this.voteId = voteId;
        this.voterId = voterId;
        this.candidateId = candidateId;
        this.timestamp = timestamp;
        this.electionId = electionId;
        this.additionalInfo = additionalInfo;
    }
} 