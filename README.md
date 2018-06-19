# ID-based-cryptography

## Overview
IDベース暗号をC言語で実装できるかなってやつ
  
## 使用ライブラリ
 - OpenSSL (OpenSSL 1.0.2k-fips  26 Jan 2017)
 - GMP (The GNU Multiple Precision Arithmetic Library)
 - TEPLA (University of Tsukuba Elliptic Curve and Pairing Library)
 
 
 ## 実装内容
 ### 主に以下の画像の流れで実装
 詳細は後々自分のブログ(github.io)にあげるつもり  
 今は以下の説明だけ仮設置  
 概要は[ココ](https://github.com/jpfaw/ID-based-cryptography/blob/README_file/images/ID%E3%83%98%E3%82%99%E3%83%BC%E3%82%B9%E6%9A%97%E5%8F%B7%E3%81%AE%E5%AE%9F%E8%A3%85.pdf)
 
 ### セットアップ部分
 ![鍵生成](https://github.com/jpfaw/ID-based-cryptography/blob/README_file/images/key_create.png?raw=true)
 
 ### 暗号化
  ![暗号化](https://github.com/jpfaw/ID-based-cryptography/blob/README_file/images/encode.png?raw=true)
  
  ### 復号
   ![復号](https://github.com/jpfaw/ID-based-cryptography/blob/README_file/images/decode.png?raw=true)
