package com.bjut.blockchain.web.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletResponse;
import java.io.*;

@Controller
public class DownLoadController {
    @GetMapping("/download")
    public void downloadZipFile(HttpServletResponse response) {
        try {
            // 设置响应的内容类型和文件名
            response.setContentType("application/zip");
            response.setHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=AirTicket-client.zip");

            // 创建文件输入流
            //FIXME: 修改文件名与压缩包名称一样
            File file = new File("BlockChain.zip");
            FileInputStream inStream = new FileInputStream(file);
            BufferedInputStream bin = new BufferedInputStream(inStream);

            // 获取响应的输出流并写入文件内容
            OutputStream outStream = response.getOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead;

            while ((bytesRead = bin.read(buffer)) != -1) {
                outStream.write(buffer, 0, bytesRead);
            }

            // 关闭流
            bin.close();
            outStream.close();
        } catch (IOException e) {
            // 处理异常，例如打印日志或返回错误响应
            e.printStackTrace();
        }
    }
}
