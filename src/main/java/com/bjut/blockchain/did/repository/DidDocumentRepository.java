package com.bjut.blockchain.did.repository;

import com.bjut.blockchain.did.entity.DidDocumentEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

// import java.util.List; // 如果添加自定义查询方法并返回列表

@Repository // 声明这是一个Spring管理的仓库Bean
public interface DidDocumentRepository extends JpaRepository<DidDocumentEntity, String> {
    // JpaRepository<EntityType, IDType>
    // Spring Data JPA 会自动为这个接口提供标准的CRUD方法实现，例如：
    // - save(entity)
    // - findById(id)
    // - findAll()
    // - deleteById(id)
    // - count()
    // - existsById(id)

    // List<DidDocumentEntity> findBySomeProperty(String someProperty);
    // Optional<DidDocumentEntity> findFirstByOrderByCreatedAtDesc();
}