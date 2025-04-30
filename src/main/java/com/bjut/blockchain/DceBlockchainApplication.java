package com.bjut.blockchain;

import com.bjut.blockchain.web.util.IntegrityChecker;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DceBlockchainApplication {

  public static void main(String[] args) {
        //使用jar运行前放开
        if (true || IntegrityChecker.verifyIntegrity()) {
            System.out.println("Code integrity verified. Starting the application...");
            SpringApplication.run(DceBlockchainApplication.class, args);
        } else {
            System.err.println("Code integrity check failed. Application cannot start.");
        }
    }

}
