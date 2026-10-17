# 完整HTTP验证报文

以下文件保留方法、实际URL、请求头、请求体、响应头与完整响应体；Markdown展示统一使用LF换行，响应体是HTTP客户端解码分块传输后的完整实体；只有认证值使用占位符。每个用例的创建与最后状态均保留，目标与规则全部为自建合成数据。这里保存最后分页，不重复提交每次轮询。TCP逻辑覆盖另由独立数据库清单核验。

验证点：完整端口覆盖、共享请求准入、逐模板凭证；没有真实漏洞利用，验证状态为未利用。原临时环境已释放，请在自己的隔离环境替换URL/令牌后复现。

- [r4-baseline-bulk128.md](r4-baseline-bulk128.md)
- [r4-candidate-bulk128.md](r4-candidate-bulk128.md)
- [r3-candidate-http128.md](r3-candidate-http128.md)
- [r3-candidate-web128.md](r3-candidate-web128.md)
- [r3-candidate-nuclei-smoke.md](r3-candidate-nuclei-smoke.md)
- [r3-candidate-quiet.md](r3-candidate-quiet.md)
- [r5-candidate-calibration-worker-0.md](r5-candidate-calibration-worker-0.md)
- [r5-candidate-calibration-worker-1.md](r5-candidate-calibration-worker-1.md)
- [r5-candidate-split.md](r5-candidate-split.md)
