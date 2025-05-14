package com.bjut.blockchain.web.controller;

import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.ResponseEntity; // 如果需要返回 ResponseEntity
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.alibaba.fastjson.JSON;
import com.bjut.blockchain.web.model.Block; // 导入 Block 类型
import com.bjut.blockchain.web.service.BlockService;
import com.bjut.blockchain.web.service.PowService;
import com.bjut.blockchain.web.util.BlockCache;

/**
 * 用于管理区块链操作的 REST 控制器。
 * 所有端点都在 /api/blocks 路径下。
 */
@RestController
@RequestMapping("/api/blocks")
public class BlockController {

    private final BlockService blockService;
    private final PowService powService;
    private final BlockCache blockCache;

    @Autowired
    public BlockController(BlockService blockService, PowService powService, BlockCache blockCache) {
        this.blockService = blockService;
        this.powService = powService;
        this.blockCache = blockCache;
    }

    /*
    // 这个登录端点与 DidController 中的登录功能可能冲突或重复。
    // 如果不再需要，可以删除。如果需要，请确保路径不冲突。
    @PostMapping("/login-block") // 例如，修改路径以避免冲突
    public ResponseEntity<Boolean> login(String username, String password) {
        // 实际的登录逻辑...
        return ResponseEntity.ok(true);
    }
    */

    /**
     * 查看当前节点完整的区块链数据。
     * 路径: GET /api/blocks/chain
     * @return JSON字符串表示的区块链
     */
    @GetMapping("/chain")
    public String getCurrentBlockchain() {
        return JSON.toJSONString(blockCache.getBlockChain());
    }

    /**
     * 查看当前节点已打包的交易数据。
     * 路径: GET /api/blocks/transactions/packed
     * @return JSON字符串表示的已打包交易
     */
    @GetMapping("/transactions/packed")
    public String getPackedTransactions() {
        return JSON.toJSONString(blockCache.getPackedTransactions());
    }

    /**
     * 创建创世区块。
     * 路径: POST /api/blocks/genesis
     * @return JSON字符串表示的区块链 (包含创世块)
     */
    @PostMapping("/genesis")
    public String createGenesisBlock() {
        blockService.createGenesisBlock();
        return JSON.toJSONString(blockCache.getBlockChain());
    }

    /**
     * 通过工作量证明 (PoW) 挖矿生成新的区块。
     * 路径: POST /api/blocks/mine
     * @return JSON字符串表示的新挖出的区块，或者挖矿失败的信息
     */
    @PostMapping("/mine") // 这是您错误定位到的方法附近
    public String mineNewBlock() {
        // 调用 powService.mine()，它现在应该返回一个 Block 对象或 null
        Block newBlock = powService.mine(); // <--- 修改: 接收 Block 对象

        if (newBlock != null) {
            // 挖矿成功，返回新挖出的区块
            // 假设 powService.mine() 成功后，blockCache 已经更新
            // 或者 newBlock 对象本身就是最新的区块数据
            System.out.println("挖矿成功，新区块哈希: " + newBlock.getHash());
            return JSON.toJSONString(newBlock); // 直接返回新区块的JSON
        } else {
            // 挖矿失败或没有新的交易可打包
            System.out.println("挖矿失败或没有新的交易可打包。");
            return JSON.toJSONString("挖矿失败或没有新的交易可打包。");
        }
    }

    /**
     * 查看当前节点待处理的交易数据。
     * 路径: GET /api/blocks/transactions/pending
     * @return JSON字符串表示的待处理交易
     */
    @GetMapping("/transactions/pending")
    public String getPendingTransactions() {
        // 假设 BlockCache 或 BlockService 有方法获取待处理交易
        // return JSON.toJSONString(blockCache.getPendingTransactions()); // 示例
        return JSON.toJSONString("此功能待实现：获取待处理交易"); // 占位符
    }
}
