package com.bjut.blockchain;

import com.bjut.blockchain.web.service.NodeJoinAndQuit;
import com.bjut.blockchain.web.util.HttpRequestUtil;
import com.bjut.blockchain.web.util.IntegrityChecker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.annotation.PostConstruct;

@SpringBootApplication
public class DceBlockchainApplication {

    @Autowired
    private NodeJoinAndQuit nodeJoinAndQuit;

    public static void main(String[] args) {
        //XXX： 删除true会启动时进行代码完整性检查 请确保使用Java -jar运行 且IntegrityChecker文件和py文件的jar包名相同
        if (true || IntegrityChecker.verifyIntegrity()) {
            System.out.println("Code integrity verified. Starting the application...");
            SpringApplication.run(DceBlockchainApplication.class, args);
        } else {
            System.err.println("Code integrity check failed. Application cannot start.");
        }
    }

    @PostConstruct
    public void init() {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                nodeJoinAndQuit.selfQuit();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }));
    }
}

