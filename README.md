# 多引擎协同流量异常检测引擎

面向内网流量巡检场景的轻量异常检测引擎，融合无监督算法、专家规则与威胁情报三类检测能力，无需标注数据即可实现高精度流量异常识别，支持PCAP离线批量分析与网卡实时流式检测双模式。

## ✨ 核心特性
- 🔍 **三引擎融合检测**：采用「规则引擎 + 无监督ML引擎 + 威胁情报引擎」三引擎加权融合架构，通过工厂模式实现引擎可插拔，解决单一算法误报率高的问题
- 📊 **深度特征工程**：支持40+维流量特征提取，覆盖基础统计、协议深度、时序行为三大维度，精准刻画流量行为模式
- 📚 **RAG威胁知识增强**：内置常见攻击类型与处置建议知识库，通过语义检索为异常结果注入领域知识，自动标注攻击类型与处置方案
- ⚡ **双运行模式**：支持PCAP文件离线批量分析与网卡实时抓包流式检测两种模式，适配不同运营场景
- 🐳 **容器化部署**：提供Docker多阶段构建镜像，支持旁挂部署，可快速集成进安全运营工具链
- 🛡️ **生产级规范**：统一引擎抽象基类、标准化错误处理、可配置权重参数，符合企业级工具开发规范

## 🏗️ 系统架构
### 三引擎融合检测架构

流量输入 → 特征提取
↓
┌─────────────────────────────────┐
│  规则引擎  │  ML 引擎  │  情报引擎  │
│  (0.3 权重) │ (0.35 权重) │ (0.35 权重) │
└─────────────────────────────────┘
↓
融合打分排序 → RAG 知识注入 → 异常告警输出


## 🛠️ 技术栈
| 类别 | 技术 |
|------|------|
| 核心语言 | Python 3.10+ |
| 流量解析 | Scapy |
| 检测算法 | 孤立森林 Isolation Forest、专家规则、IOC匹配 |
| 知识增强 | RAG 语义检索、BGE 嵌入模型 |
| Web框架 | FastAPI + Uvicorn |
| 工程化 | Git、Docker |

## 📈 能力覆盖
- **端口扫描检测**：识别快速端口扫描、慢速扫描等多种探测行为
- **暴力破解检测**：针对SSH/FTP/数据库等服务的密码枚举攻击检测
- **异常大流量检测**：识别数据渗出、DDoS攻击等大流量异常
- **威胁情报匹配**：内置恶意IP/域名库，命中即高优先级告警
- **行为异常检测**：基于无监督算法识别偏离基线的异常流量行为

## 🚀 快速开始
### 环境安装
```bash
# 克隆仓库
git clone https://github.com/Wenduowang22/traffic-anomaly-detector.git
cd traffic-anomaly-detector

# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt

离线 PCAP 分析
from src.detectors.fusion_engine import FusionDetector

# 初始化融合检测器
detector = FusionDetector()

# 加载PCAP并解析特征
# flows = parse_pcap("sample.pcap")

# 执行检测
results = detector.detect(flows)
print(f"检测到异常流: {len(results)} 条")

启动 API 服务
python run.py
接口文档地址：http://localhost:8000/docs

## 📁 项目结构
traffic-anomaly-detector/
├── src/
│   ├── detectors/           # 多引擎检测模块
│   │   ├── base.py             # 引擎抽象基类
│   │   ├── rule_engine.py      # 专家规则引擎
│   │   ├── ml_engine.py        # 无监督ML引擎
│   │   ├── ioc_engine.py       # 威胁情报引擎
│   │   └── fusion_engine.py    # 融合打分器
│   ├── rag/                 # 威胁知识库RAG模块
│   │   ├── embedding.py        # 向量嵌入服务
│   │   └── retriever.py        # 知识库检索器
│   ├── traffic_parser.py    # 流量解析与特征提取
│   └── utils.py             # 工具函数
├── api/                    # FastAPI接口层
├── data/                   # 测试数据目录
├── requirements.txt        # 依赖清单
├── run.py                  # 服务启动入口
└── README.md

📧 联系方式
- Wenduo Wang
- wenduowang22@163.com
