package com.bjut.blockchain.web.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "pending_transactions")
@Getter
@Setter
@NoArgsConstructor
public class PendingTransactionEntity {

    @Id // 交易ID作为主键
    @Column(name = "transaction_id", length = 255, nullable = false, unique = true)
    private String id;

    @Column(name = "public_key", columnDefinition = "TEXT") // 公钥可能较长
    private String publicKey;

    @Column(name = "sign", columnDefinition = "TEXT") // 签名也可能较长
    private String sign;

    @Column(name = "tx_timestamp") // 注意避免与SQL关键字冲突，故使用 tx_timestamp
    private long timestamp;

    @Lob // 交易数据内容可能很大
    @Column(name = "data_content", nullable = false, columnDefinition = "TEXT") // 假设data不应为空
    private String data;

    // 可以添加一个字段来记录交易被添加到池中的时间，用于排序或清理策略
    @Column(name = "added_to_pool_at", nullable = false, updatable = false)
    private Long addedToPoolAt;

    @PrePersist
    protected void onCreate() {
        if (this.addedToPoolAt == null) {
            this.addedToPoolAt = System.currentTimeMillis();
        }
    }

    // 构造函数，方便从 Transaction 模型转换
    public PendingTransactionEntity(String id, String publicKey, String sign, long timestamp, String data) {
        this.id = id;
        this.publicKey = publicKey;
        this.sign = sign;
        this.timestamp = timestamp;
        this.data = data;
    }
}