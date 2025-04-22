package com.example.blockchain;

import java.util.ArrayList;
import com.google.gson.GsonBuilder;

public class NoobChain {

    public static ArrayList<Block> blockchain = new ArrayList<Block>();

    public static void main(String[] args){
        blockchain.add(new Block("Hi im the first block", "0"));
        blockchain.add(new Block("Yo im the second block",blockchain.getLast().hash));
        blockchain.add(new Block("Hey im the third block",blockchain.getLast().hash));

        if(isChainValid()) {
            System.out.println("Chain is valid");
            String blockchainJson = new GsonBuilder().setPrettyPrinting().create().toJson(blockchain);
            System.out.println(blockchainJson);
        }else{
            System.out.println("Chain is invalid");
        }
    }

    public static Boolean isChainValid() {
        Block currentBlock;
        Block previousBlock;

        for(int i=1; i < blockchain.size(); i++) {
            currentBlock = blockchain.get(i);
            previousBlock = blockchain.get(i-1);

            if(!currentBlock.hash.equals(currentBlock.calculateHash()) ){
                System.out.println("Current Hashes not equal");
                return false;
            }

            if(!previousBlock.hash.equals(currentBlock.previousHash) ) {
                System.out.println("Previous Hashes not equal");
                return false;
            }
        }
        return true;
    }
}
