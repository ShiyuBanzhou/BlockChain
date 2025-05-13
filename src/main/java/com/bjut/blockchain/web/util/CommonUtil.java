package com.bjut.blockchain.web.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.UUID;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class CommonUtil{
    // ObjectMapper 是线程安全的，可以作为静态实例重用
    private static final ObjectMapper objectMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT); // 可选：使 JSON 输出更易读

    /**
     * 生成基于 UUID 的随机字符串，移除连字符。
     *
     * @return 不含连字符的 UUID 字符串。
     */
    public static String generateUuid() {
        return UUID.randomUUID().toString().replaceAll("-", "");
    }

    /**
     * 将公钥 PublicKey 对象转换为 Base64 编码的字符串。
     *
     * @param publicKey 要编码的公钥对象。
     * @return Base64 编码的公钥字符串。
     */
    public static String keyToString(PublicKey publicKey) {
        byte[] keyBytes = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    /**
     * 将对象转换为 JSON 字符串。
     * 使用 Jackson ObjectMapper 进行序列化。
     *
     * @param obj 要转换为 JSON 的对象。
     * @return JSON 格式的字符串。
     * @throws JsonProcessingException 如果序列化过程中发生错误。
     */
    public static String getJson(Object obj) throws JsonProcessingException {
        if (obj == null) {
            return null;
        }
        return objectMapper.writeValueAsString(obj);
    }

    /**
     * 计算给定字符串的 SHA-256 哈希值。
     * 内部调用 CryptoUtil 的 applySha256 方法。
     *
     * @param input 要计算哈希的输入字符串。
     * @return 输入字符串的 SHA-256 哈希值（通常为十六进制字符串）。
     */
    public static String calculateHash(String input) {
        if (input == null) {
            // 或者根据需要抛出异常
            return null;
        }
        // 调用 CryptoUtil 中已有的 SHA-256 方法
        return CryptoUtil.applySha256(input);
    }
    /**
     * 获取本地ip
     * @return
     */
    public static String getLocalIp() {
		try {
            InetAddress ip4 = InetAddress.getLocalHost();
            return ip4.getHostAddress();
		} catch (UnknownHostException e) {
			e.printStackTrace();
        }
        return "";
    }
    /**
     * 构建标准的API响应实体。
     * @param code HTTP状态码。
     * @param msg 响应消息。
     * @param data 响应数据对象。
     * @return ResponseEntity 实例。
     */
    public static ResponseEntity<String> getResponse(int code, String msg, Object data) {
        ObjectNode responseJson = objectMapper.createObjectNode();
        responseJson.put("code", code);
        responseJson.put("msg", msg);

        if (data != null) {
            // 将数据对象转换为JSON节点
            responseJson.set("data", objectMapper.valueToTree(data));
        } else {
            // 如果数据为null，则在JSON中明确表示为null
            responseJson.putNull("data");
        }

        try {
            // 将JSON对象转换为字符串并创建ResponseEntity
            return new ResponseEntity<>(objectMapper.writeValueAsString(responseJson), HttpStatus.valueOf(code));
        } catch (Exception e) {
            // 处理JSON转换或HTTP状态码无效的异常
            ObjectNode errorJson = objectMapper.createObjectNode();
            errorJson.put("code", HttpStatus.INTERNAL_SERVER_ERROR.value());
            errorJson.put("msg", "处理响应时发生内部错误: " + e.getMessage());
            try {
                return new ResponseEntity<>(objectMapper.writeValueAsString(errorJson), HttpStatus.INTERNAL_SERVER_ERROR);
            } catch (Exception ex) {
                // 极端情况下的回退
                return new ResponseEntity<>("{\"code\":500,\"msg\":\"处理响应时发生严重错误\"}", HttpStatus.INTERNAL_SERVER_ERROR);
            }
        }
    }
}