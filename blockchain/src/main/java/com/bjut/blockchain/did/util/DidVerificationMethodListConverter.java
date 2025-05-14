package com.bjut.blockchain.did.util;

import com.bjut.blockchain.did.model.DidDocument.VerificationMethod;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.io.IOException;
import java.util.ArrayList; // 导入 ArrayList
import java.util.Collections;
import java.util.List;

@Converter // 标记为JPA转换器，autoApply=true 可以使其自动应用于所有匹配类型的属性
public class DidVerificationMethodListConverter implements AttributeConverter<List<VerificationMethod>, String> {

    private static final Logger logger = LoggerFactory.getLogger(DidVerificationMethodListConverter.class);
    // 建议在应用上下文中管理ObjectMapper的单个实例，但对于转换器，通常会新建或静态共享。
    // 为简单起见，此处新建。
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String convertToDatabaseColumn(List<VerificationMethod> attributeList) {
        // 将 List<VerificationMethod> 转换为 JSON 字符串
        if (attributeList == null || attributeList.isEmpty()) {
            return "[]"; // 对于空列表，存储为JSON空数组字符串，而不是null，以避免反序列化问题
        }
        try {
            return objectMapper.writeValueAsString(attributeList);
        } catch (JsonProcessingException e) {
            logger.error("无法将VerificationMethod列表转换为JSON字符串: {}", e.getMessage(), e);
            // 根据您的错误处理策略，可以返回null或抛出运行时异常
            throw new IllegalArgumentException("转换VerificationMethod列表到JSON时出错", e);
        }
    }

    @Override
    public List<VerificationMethod> convertToEntityAttribute(String dbDataJson) {
        // 将 JSON 字符串转换回 List<VerificationMethod>
        if (dbDataJson == null || dbDataJson.trim().isEmpty() || "null".equalsIgnoreCase(dbDataJson.trim())) {
            return new ArrayList<>(); // 对于null或空JSON，返回空列表
        }
        try {
            // 使用 TypeReference 来帮助Jackson正确反序列化泛型列表
            return objectMapper.readValue(dbDataJson, new TypeReference<List<VerificationMethod>>() {});
        } catch (IOException e) {
            logger.error("无法将JSON字符串 '{}' 转换为VerificationMethod列表: {}", dbDataJson, e.getMessage(), e);
            // 根据您的错误处理策略，可以返回空列表或抛出运行时异常
            throw new IllegalArgumentException("转换JSON到VerificationMethod列表时出错", e);
        }
    }
}