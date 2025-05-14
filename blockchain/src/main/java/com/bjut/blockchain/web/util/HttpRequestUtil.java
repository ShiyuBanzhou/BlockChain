package com.bjut.blockchain.web.util;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * @author 18500980264
 */
/**
 * HttpRequestUtil 类用于简化 HTTP 请求的处理过程
 */
public class HttpRequestUtil {

    /**
     * 执行 HTTP POST 请求，请求体为 JSON 格式
     *
     * @param jsonValueString JSON 格式的请求体字符串
     * @param url 请求的 URL 地址
     * @return 返回响应体字符串
     * @throws Exception 抛出异常，如果请求过程中发生错误
     */
    public static String httpPost(String jsonValueString, String url) throws Exception {
        System.out.println(jsonValueString);
        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        // 添加请求头
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        con.setDoOutput(true);
        // 获取输出流并写入请求体
        try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
            wr.writeBytes(jsonValueString);
            wr.flush();
            System.out.println(wr);
        }
        System.out.println(con);

        int responseCode = con.getResponseCode();
        System.out.println("POST Response Code :: " + responseCode);
        return getResult(con, responseCode);
    }

    /**
     * 执行 HTTP POST 请求，请求体为表单格式
     *
     * @param valueString 表单格式的请求体字符串
     * @param url 请求的 URL 地址
     * @return 返回响应体字符串
     * @throws Exception 抛出异常，如果请求过程中发生错误
     */
    public static String httpPostForm(String valueString, String url) throws Exception {
        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        // 添加请求头
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        con.setDoOutput(true);
        // 获取输出流并写入请求体
        try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
            wr.writeBytes(valueString);
            wr.flush();
        }
        int responseCode = con.getResponseCode();
        System.out.println(con.toString());
        System.out.println("POST Response Code :: " + responseCode);
        return getResult(con, responseCode);
    }

    /**
     * 执行 HTTP GET 请求
     *
     * @param url 请求的 URL 地址
     * @return 返回响应体字符串
     * @throws Exception 抛出异常，如果请求过程中发生错误
     */
    public static String httpGet(String url) throws Exception {
        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        // 设置请求方法为 GET
        con.setRequestMethod("GET");
        int responseCode = con.getResponseCode();
        System.out.println(con.toString());
        System.out.println("GET Response Code :: " + responseCode);
        return getResult(con, responseCode);
    }

    /**
     * 获取 HTTP 请求的响应结果
     *
     * @param con HTTP 连接对象
     * @param responseCode 响应码
     * @return 返回响应体字符串，如果响应码不是 HTTP_OK，则返回 null
     * @throws IOException 抛出 IOException，如果读取响应过程中发生错误
     */
    private static String getResult(HttpURLConnection con, int responseCode) throws IOException {
        if (responseCode == HttpURLConnection.HTTP_OK) {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                String inputLine;
                StringBuilder response = new StringBuilder();

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                return response.toString();
            }
        } else {
            return null;
        }
    }
}

