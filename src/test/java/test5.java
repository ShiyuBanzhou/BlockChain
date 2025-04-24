import com.d208.blockchain.model.Block;
import com.d208.blockchain.model.Transaction;

import java.util.ArrayList;
import java.util.List;

public class test5 {
    static List<Transaction> txPool = new ArrayList<>();


    public static void updateTxPool(Block block){
        List<Transaction> list = block.getTransactionList();
        for (Transaction transaction : list) {
            txPool.remove(transaction);
        }
    }
    public static void main(String[] args) {

    }
}
