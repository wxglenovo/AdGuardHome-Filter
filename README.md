AdGuardHome Rules 简介
1. 触发条件

定时触发：每天 UTC 0 点和 12 点自动运行。

手动触发：支持在 GitHub Actions 页面点击 “Run workflow” 手动执行。

2. 权限

contents: write
允许 workflow 自动提交文件到仓库，并创建 Release。

3. 工作流程步骤
(1) Checkout 仓库

使用 actions/checkout@v4 拉取当前仓库代码，确保后续可以提交更新。

(2) 下载 & 合并规则

多个远程规则 URL 下载到临时文件夹 tmp/all.txt。

过滤规则：

生成最终规则文件 dist/AdGuardHome.txt：

文件头部加入生成日期和规则总数信息。

保留干净、去重后的规则内容。

生成 Release Tag，格式为 rules-YYYYMMDD，保证 GitHub Release 合法。

(3) 对比规则差异

与历史规则文件 old_rules.txt 对比。

计算新增条数 diff_count，记录总条数 new_count。

更新 old_rules.txt 为最新规则。

(4) 提交 & 推送

配置 Git 用户信息。

自动添加并提交更新的规则文件。

如果没有新增规则，跳过提交。

使用 GITHUB_TOKEN 自动推送到远程仓库。

(5) 创建 Release

仅当有新增规则时触发。

使用 softprops/action-gh-release@v2 创建 Release。

Release 名称包含总规则数，Body 描述新增条数。

附带 dist/AdGuardHome.txt 文件。

(6) 显示规则统计

输出总规则数、新增规则数。

展示规则文件前 50 行，便于日志查看。

4. 特点

自动化：定时+手动触发。

干净规则：去掉注释和空行，去重处理。

自动统计：生成文件头部带日期和总条数。

自动提交 & Release：新增规则自动提交、创建 Release，方便同步更新。

GitHub Release tag 合法，避免创建失败。
