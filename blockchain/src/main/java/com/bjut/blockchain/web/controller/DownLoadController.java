package com.bjut.blockchain.web.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Controller; // 保持 @Controller 因为它直接写响应流
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping; // 添加 RequestMapping
// import org.springframework.web.bind.annotation.CrossOrigin; // 如果WebConfig中已配置全局CORS，这里通常可以省略

import javax.servlet.http.HttpServletResponse;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * 用于处理文件下载的控制器。
 * 所有端点都在 /api/downloads 路径下。
 */
@Controller // 对于直接操作HttpServletResponse写文件流的场景，@Controller是合适的
@RequestMapping("/api/downloads") // <--- 添加: API基础路径
// @CrossOrigin // 如果WebConfig中已配置全局CORS，这里通常可以省略
public class DownLoadController {

    // 定义要下载的文件名和路径，可以考虑从配置中读取
    private static final String CLIENT_ZIP_FILENAME = "AirTicket-client.zip";
    private static final String CLIENT_ZIP_FILE_PATH = "BlockChain.zip"; // FIXME: 确保这个路径是正确的，并且与文件名一致

    /**
     * 下载客户端ZIP文件。
     * 路径: GET /api/downloads/client-zip
     * @param response HttpServletResponse 用于写入文件内容
     */
    @GetMapping("/client-zip") // <--- 修改: 路径更具体 (原 /download)
    public void downloadClientZipFile(HttpServletResponse response) {
        File file = new File(CLIENT_ZIP_FILE_PATH);

        if (!file.exists() || !file.isFile()) {
            // 文件不存在或不是一个文件，返回404
            try {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "请求的文件未找到: " + CLIENT_ZIP_FILENAME);
            } catch (IOException e) {
                e.printStackTrace(); // 记录错误
            }
            return;
        }

        response.setContentType("application/zip");
        response.setHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + CLIENT_ZIP_FILENAME + "\""); // 使用双引号包裹文件名
        response.setContentLengthLong(file.length()); // 设置文件大小，有助于客户端显示下载进度

        try (FileInputStream inStream = new FileInputStream(file);
             BufferedInputStream bin = new BufferedInputStream(inStream);
             OutputStream outStream = response.getOutputStream()) {

            byte[] buffer = new byte[4096]; // 使用稍大一点的缓冲区
            int bytesRead;

            while ((bytesRead = bin.read(buffer)) != -1) {
                outStream.write(buffer, 0, bytesRead);
            }
            outStream.flush(); // 确保所有数据都被写出
        } catch (IOException e) {
            // 处理IO异常，例如客户端断开连接等
            System.err.println("下载文件时发生IO错误: " + e.getMessage());
            // 此时可能无法再向response写入错误信息，因为头部可能已经发送
            // e.printStackTrace();
        }
    }
}
