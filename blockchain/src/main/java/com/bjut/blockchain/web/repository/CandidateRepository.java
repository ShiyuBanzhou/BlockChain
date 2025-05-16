package com.bjut.blockchain.web.repository;

import com.bjut.blockchain.web.entity.CandidateEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CandidateRepository extends JpaRepository<CandidateEntity, String> {

    List<CandidateEntity> findByElectionId(String electionId);
} 