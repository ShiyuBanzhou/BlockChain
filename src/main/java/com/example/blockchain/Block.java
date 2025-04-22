package com.example.blockchain;

import java.util.Date;
public class Block {

    public String hash;
    public String previousHash;
    private String data;
    private long timeStamp;

    // Block构造器
    public Block(String data, String previousHash) {
        this.data = data;
        this.previousHash = previousHash;
        this.timeStamp = new Date().getTime();
        this.hash = calculateHash();
    }

    public String calculateHash() {
        return StringUtil.applySha256(previousHash + timeStamp + data);
    }

}
