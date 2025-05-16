package com.bjut.blockchain.web.repository;

import com.bjut.blockchain.web.entity.ElectionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ElectionRepository extends JpaRepository<ElectionEntity, String> {

    List<ElectionEntity> findAllByOrderByCreatedAtDesc();
    
    List<ElectionEntity> findByStatusOrderByStartTimeAsc(String status);
    
    List<ElectionEntity> findByCreatorIdOrderByCreatedAtDesc(String creatorId);
} 