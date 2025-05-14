package com.bjut.blockchain.web.repository;

import com.bjut.blockchain.web.entity.PendingTransactionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional; // 导入事务注解

import java.util.Collection; // 使用 Collection 而不是 List 以获得更大的灵活性
import java.util.List;

@Repository
public interface PendingTransactionRepository extends JpaRepository<PendingTransactionEntity, String> {

    List<PendingTransactionEntity> findAllByOrderByAddedToPoolAtAsc();

    void deleteAllByIdIn(Collection<String> ids); // 使用deleteAllByIdIn并接受一个ID的集合

}