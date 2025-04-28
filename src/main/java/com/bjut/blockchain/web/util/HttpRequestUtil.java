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
public class HttpRequestUtil {
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

    public static String httpPostForm(String ValueString, String url) throws Exception {
        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        // 添加请求头
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        con.setDoOutput(true);
        // 获取输出流并写入请求体
        try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
            wr.writeBytes(ValueString);
            wr.flush();
        }
        int responseCode = con.getResponseCode();
        System.out.println(con.toString());
        System.out.println("POST Response Code :: " + responseCode);
        return getResult(con, responseCode);
    }


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
