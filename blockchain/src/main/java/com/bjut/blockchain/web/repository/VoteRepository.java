package com.bjut.blockchain.web.repository;

import com.bjut.blockchain.web.entity.VoteEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface VoteRepository extends JpaRepository<VoteEntity, String> {

    List<VoteEntity> findByElectionId(String electionId);
    
    List<VoteEntity> findByVoterId(String voterId);
    
    List<VoteEntity> findByElectionIdAndVoterId(String electionId, String voterId);
    
    List<VoteEntity> findByAddedToBlockchain(boolean addedToBlockchain);
    
    @Query("SELECT v.candidateId, COUNT(v) as voteCount FROM VoteEntity v WHERE v.electionId = :electionId GROUP BY v.candidateId")
    List<Object[]> countVotesByCandidateForElection(@Param("electionId") String electionId);
    
    boolean existsByElectionIdAndVoterId(String electionId, String voterId);
} 