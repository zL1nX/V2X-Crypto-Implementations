# V2X-Crypto-Implementations

> 代码备份(❌)，垃圾回收(✅）
> 一份包含各类密码算法实现的V2X仿真仓库

### 环境
- OMNET++ & VEINS
- Debian & Gcc
- OpenSSL & GmSSL

### 内容
- 包含ECQV、ECDSA、ECDH、SM2Sign、SM2Kap在OMNET++车联网环境下的实现
- 包括以上算法在VEINS的DSRC协议栈中的实现（由于当时C-V2X的仿真实现成果非常有限，而且许多框架不支持自定义应用层消息，所以只好自己手撸一个了）
- 一言以蔽之：车联网中ECQV轻量证书的国密实现与隐私保护协议

### 剩余内容
- 隐私保护的算法实现与仿真实现
- 该隐私保护协议为自己设计，基于SM9群签名，并在代码中进行了完整是吸纳

> 别喷了，真不会写C/C++
