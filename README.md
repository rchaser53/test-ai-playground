# API Fuzzing Test Sample

このプロジェクトは、Node.js/Express APIサーバに対する包括的なファジングテストのサンプル実装です。セキュリティ脆弱性の検出、パフォーマンステスト、エッジケースの処理能力を評価するための自動化されたテストスイートを提供します。

## 🚀 特徴

### ファジングテストの種類
- **基本APIファジング**: ランダムなペイロードでのAPI動作検証
- **セキュリティファジング**: SQLインジェクション、XSS、CSRF等の脆弱性テスト
- **パフォーマンスファジング**: 負荷・ストレステスト
- **エッジケーステスト**: 極端な入力値での動作確認

### セキュリティテスト項目
- SQLインジェクション (Union-based, Blind, Time-based)
- NoSQLインジェクション
- XSS (Cross-Site Scripting)
- XXE (XML External Entity)
- CSRF (Cross-Site Request Forgery)
- パストラバーサル攻撃
- HTTPヘッダーインジェクション
- SSRF (Server-Side Request Forgery)
- セッション固定化攻撃
- HTTPレスポンス分割攻撃

### パフォーマンステスト項目
- レスポンス時間測定
- 同時接続負荷テスト
- メモリ使用量監視
- レート制限テスト
- 大容量データ処理テスト

## 📦 セットアップ

### 前提条件
- Node.js 16以上
- npm または yarn

### インストール
```bash
# 依存関係のインストール
npm install

# 開発用依存関係も含めてインストール
npm install --include=dev
```

## 🏃‍♂️ 使用方法

### サーバーの起動
```bash
# 開発モード（ホットリロード有効）
npm run dev

# 本番モード
npm start
```

サーバーは `http://localhost:3000` で起動します。

### 個別テストの実行

#### 基本APIファジングテスト
```bash
npm run test:fuzzing
# または
npm test tests/fuzzing/api-fuzzing.test.js
```

#### セキュリティファジングテスト
```bash
npm test tests/fuzzing/security-fuzzing.test.js
```

#### パフォーマンスファジングテスト
```bash
npm test tests/fuzzing/performance-fuzzing.test.js
```

### 包括的なファジングテスト実行
```bash
# 全ファジングテストの実行とレポート生成
node scripts/run-fuzzing-tests.js
```

このコマンドは以下を実行します：
1. 全ファジングテストスイートの実行
2. コードカバレッジレポートの生成
3. HTML形式の包括的レポート生成 (`fuzzing-report.html`)
4. JSON形式の詳細データ出力 (`fuzzing-report.json`)

### テストのみ実行（サーバー起動なし）
```bash
npm test
```

## 🎯 APIエンドポイント

### ユーザー管理
- `GET /api/users` - ユーザー一覧取得（ページネーション対応）
- `GET /api/users/:id` - 特定ユーザー取得
- `POST /api/users` - ユーザー作成
- `PUT /api/users/:id` - ユーザー更新
- `DELETE /api/users/:id` - ユーザー削除

### 投稿管理
- `GET /api/posts` - 投稿一覧取得
- `POST /api/posts` - 投稿作成

### その他
- `GET /health` - ヘルスチェック
- `GET /api/search?query=...` - ユーザー検索
- `POST /api/upload` - ファイルアップロード（テスト用）

## 🧪 ファジングテストの詳細

### 生成されるランダムデータ

#### 文字列データ
- 通常の英数字文字列
- 特殊文字を含む文字列
- Unicode文字（絵文字、多言語）
- SQLインジェクションペイロード
- XSSペイロード
- 極端に長い文字列
- 空文字列

#### 数値データ
- 正の整数・小数
- 負の数値
- ゼロ
- 極値（Number.MAX_SAFE_INTEGER等）
- NaN、Infinity
- 文字列化された数値

#### メールアドレス
- 有効な形式
- 無効な形式（@なし、ドメインなし等）
- 特殊文字を含むもの

### セキュリティテストのペイロード例

#### SQLインジェクション
```sql
'; DROP TABLE users; --
' OR '1'='1
' UNION SELECT * FROM users --
'; WAITFOR DELAY '00:00:05' --
```

#### XSS
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')
```

#### パストラバーサル
```
../../../etc/passwd
..\\..\\..\\windows\\system32\\config\\sam
%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
```

## 📊 レポート機能

ファジングテスト完了後、以下のレポートが生成されます：

### HTMLレポート (`fuzzing-report.html`)
- 📈 テスト結果サマリー
- 📋 各テストスイートの詳細結果
- 📊 コードカバレッジ情報
- 🔒 セキュリティ推奨事項
- 🚀 パフォーマンス最適化のヒント

### JSONレポート (`fuzzing-report.json`)
- プログラム処理可能な詳細データ
- CI/CDパイプラインでの活用可能

## 🔧 カスタマイズ

### 新しいファジングテストの追加

1. `tests/fuzzing/` ディレクトリに新しいテストファイルを作成
2. `tests/utils/fuzzingHelpers.js` のヘルパー関数を活用
3. 必要に応じて新しいランダムデータ生成関数を追加

### ファジング強度の調整

テストファイル内の以下のパラメータを調整：
```javascript
const fuzzingAttempts = 50; // 試行回数
const concurrentRequests = 50; // 同時接続数
const maxDepth = 3; // ネストオブジェクトの深さ
```

### 新しいエンドポイントのテスト追加

1. `src/server.js` に新しいエンドポイントを追加
2. 対応するファジングテストを作成
3. セキュリティ・パフォーマンステストを実装

## 🛡️ セキュリティベストプラクティス

このプロジェクトでは以下のセキュリティ対策を実装しています：

### 実装済み対策
- ✅ Helmet.jsによるセキュリティヘッダー設定
- ✅ CORS設定
- ✅ レート制限
- ✅ 入力値検証
- ✅ SQLインジェクション基本防止
- ✅ ファイルアップロード制限

### 本番環境での追加推奨事項
- 🔒 HTTPS強制
- 🔑 JWT認証の実装
- 🗄️ データベース暗号化
- 📝 監査ログ
- 🚨 侵入検知システム
- 🔐 秘密情報の環境変数管理

## 📁 プロジェクト構造

```
.
├── src/
│   └── server.js              # Express APIサーバー
├── tests/
│   ├── fuzzing/
│   │   ├── api-fuzzing.test.js        # 基本APIファジング
│   │   ├── security-fuzzing.test.js   # セキュリティファジング
│   │   └── performance-fuzzing.test.js # パフォーマンスファジング
│   └── utils/
│       └── fuzzingHelpers.js          # ファジングユーティリティ
├── scripts/
│   └── run-fuzzing-tests.js           # テスト実行スクリプト
├── package.json
└── README.md
```

## 🤝 貢献

プロジェクトへの貢献を歓迎します！

1. このリポジトリをフォーク
2. フィーチャーブランチを作成 (`git checkout -b feature/amazing-feature`)
3. 変更をコミット (`git commit -m 'Add amazing feature'`)
4. ブランチにプッシュ (`git push origin feature/amazing-feature`)
5. プルリクエストを作成

## 📝 ライセンス

このプロジェクトはISCライセンスの下で公開されています。

## ⚠️ 免責事項

このプロジェクトは教育・テスト目的で作成されています。実際の本番環境で使用する際は、適切なセキュリティ監査を実施してください。また、ファジングテストは対象システムに負荷をかける可能性があるため、本番環境での実行は避けてください。

## 📞 サポート

質問や問題がある場合は、GitHubのIssuesセクションでお知らせください。

---

🎯 **Happy Fuzzing!** セキュアで堅牢なAPIの構築にお役立てください。