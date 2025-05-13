package com.bjut.blockchain.web.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class CommonUtil{
    private static final ObjectMapper objectMapper = new ObjectMapper();
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