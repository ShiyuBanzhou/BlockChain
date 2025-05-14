package com.bjut.blockchain.did.util;

import com.bjut.blockchain.did.model.DidDocument.ServiceEndpoint;
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

@Converter
public class DidServiceEndpointListConverter implements AttributeConverter<List<ServiceEndpoint>, String> {

    private static final Logger logger = LoggerFactory.getLogger(DidServiceEndpointListConverter.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String convertToDatabaseColumn(List<ServiceEndpoint> attributeList) {
        if (attributeList == null || attributeList.isEmpty()) {
            return "[]"; // 存储为JSON空数组
        }
        try {
            return objectMapper.writeValueAsString(attributeList);
        } catch (JsonProcessingException e) {
            logger.error("无法将ServiceEndpoint列表转换为JSON字符串: {}", e.getMessage(), e);
            throw new IllegalArgumentException("转换ServiceEndpoint列表到JSON时出错", e);
        }
    }

    @Override
    public List<ServiceEndpoint> convertToEntityAttribute(String dbDataJson) {
        if (dbDataJson == null || dbDataJson.trim().isEmpty() || "null".equalsIgnoreCase(dbDataJson.trim())) {
            return new ArrayList<>(); // 返回空列表
        }
        try {
            return objectMapper.readValue(dbDataJson, new TypeReference<List<ServiceEndpoint>>() {});
        } catch (IOException e) {
            logger.error("无法将JSON字符串 '{}' 转换为ServiceEndpoint列表: {}", dbDataJson, e.getMessage(), e);
            throw new IllegalArgumentException("转换JSON到ServiceEndpoint列表时出错", e);
        }
    }
}