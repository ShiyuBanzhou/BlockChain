package com.bjut.blockchain.did.entity;

import com.bjut.blockchain.did.model.DidDocument.ServiceEndpoint;
import com.bjut.blockchain.did.model.DidDocument.VerificationMethod;
import com.bjut.blockchain.did.util.DidServiceEndpointListConverter;
import com.bjut.blockchain.did.util.DidVerificationMethodListConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name = "did_documents") // 表名可以保持不变
@Getter
@Setter
@NoArgsConstructor
public class DidDocumentEntity {

    @Id
    @Column(name = "did_id", length = 255, nullable = false, unique = true)
    private String id;

    @Lob // 对于MySQL, @Lob通常会映射为 TEXT, MEDIUMTEXT, 或 LONGTEXT，取决于内容长度。
    @Column(name = "verification_methods_json", columnDefinition = "TEXT") // 明确指定为TEXT，或让Hibernate根据@Lob推断
    @Convert(converter = DidVerificationMethodListConverter.class)
    private List<VerificationMethod> verificationMethod;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "did_authentication_keys", joinColumns = @JoinColumn(name = "did_id"))
    @Column(name = "authentication_key_id")
    private List<String> authentication;

    @Lob
    @Column(name = "service_endpoints_json", columnDefinition = "TEXT") // 明确指定为TEXT
    @Convert(converter = DidServiceEndpointListConverter.class)
    private List<ServiceEndpoint> service;

    // 构造函数 (保持不变)
    public DidDocumentEntity(String id, List<VerificationMethod> verificationMethod, List<String> authentication, List<ServiceEndpoint> service) {
        this.id = id;
        this.verificationMethod = verificationMethod;
        this.authentication = authentication;
        this.service = service;
    }
}