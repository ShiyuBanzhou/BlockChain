# 区块链投票系统

基于区块链技术的投票系统，利用区块链的不可篡改特性确保投票过程的公正和透明。

## 主要功能

### 区块链核心功能
- 交易创建与验证
- 区块挖掘（基于工作量证明PoW）
- 区块链验证
- 共识机制

### 投票系统功能
- 创建和管理选举
- 添加候选人
- 安全投票（基于区块链交易）
- 实时投票结果统计
- 投票记录的不可篡改性保证

## 技术架构

### 后端技术
- Spring Boot
- JPA/Hibernate
- RESTful API
- 区块链技术（工作量证明共识算法）

### 前端技术
- HTML/CSS/JavaScript
- Bootstrap 4
- jQuery
- Chart.js (投票结果可视化)

## 系统模块

### 区块链模块
- 区块结构
- 交易处理
- 共识机制
- 链验证

### 投票模块
- 选举管理
- 候选人管理
- 投票处理
- 结果统计

### 用户模块
- 用户身份验证
- 数字签名

## 安装与部署

1. 克隆代码仓库：`git clone [仓库地址]`
2. 进入项目目录：`cd blockchain`
3. 编译项目：`mvn clean package`
4. 运行项目：`java -jar target/blockchain-*.jar`

## API文档

### 区块链API
- `GET /api/blocks/chain` - 获取完整区块链
- `POST /api/blocks/mine` - 挖矿生成新区块
- `GET /api/blocks/transactions/packed` - 查看已打包交易
- `GET /api/blocks/transactions/pending` - 查看待处理交易
- `POST /api/blocks/genesis` - 创建创世区块

### 选举API
- `GET /api/elections` - 获取所有选举
- `GET /api/elections/active` - 获取进行中选举
- `POST /api/elections` - 创建新选举
- `GET /api/elections/{electionId}` - 获取选举详情
- `PUT /api/elections/{electionId}` - 更新选举信息
- `DELETE /api/elections/{electionId}` - 删除选举

### 投票API
- `POST /api/votes` - 提交投票
- `GET /api/votes/count/{electionId}` - 获取投票统计
- `GET /api/votes/election/{electionId}` - 获取选举投票
- `GET /api/votes/voter/{voterId}` - 获取用户投票历史
- `POST /api/votes/process-pending` - 处理待处理投票

## 贡献者

- [您的名字]

## 许可证

[许可证类型]
