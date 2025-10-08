# プロパティベーステスト（Property-Based Testing）ガイド

プロパティベーステストは、システムが満たすべき性質（プロパティ）を定義し、様々な入力に対してその性質が常に成り立つことを検証するテスト手法です。

## 🎯 プロパティベーステストとは

### 従来のテストとの違い

#### **従来のテスト（Example-Based Testing）**
```javascript
test('ユーザー作成', () => {
  const response = createUser({ name: 'John', email: 'john@example.com' });
  expect(response.status).toBe(201);
});
```

#### **プロパティベーステスト**
```javascript
test('プロパティ: 有効なユーザーデータは常に成功する', () => {
  property(validUserGenerator, (userData) => {
    const response = createUser(userData);
    // プロパティ: 有効な入力に対してはサーバーエラーが発生しない
    expect(response.status).toBeLessThan(500);
  });
});
```

## 📋 実装されているプロパティ

### 1. **べき等性（Idempotent）**
同じ操作を複数回実行しても結果が変わらない性質

```javascript
property: GET /api/users を複数回実行しても同じ結果が返される
```

**期待される動作:**
- 同じクエリを複数回実行
- レスポンス構造が一致
- データが変更されない

### 2. **不変条件（Invariant）**
システムの状態が常に満たすべき条件

```javascript
property: ユーザー数は作成により増加し、削除により減少する
```

**期待される動作:**
- 作成前後でユーザー数を比較
- 削除前後でユーザー数を比較
- データの整合性が保たれる

### 3. **例外安全性（Exception Safety）**
予期しない入力に対してもシステムが安定している性質

```javascript
property: 不正な入力でもサーバーはクラッシュしない
```

**期待される動作:**
- 悪意のある入力を送信
- HTTP 5xx エラーが発生しない
- 適切なエラーメッセージを返す

### 4. **データ整合性（Data Consistency）**
作成したデータが適切に取得・操作できる性質

```javascript
property: 作成されたデータは取得可能である
```

**期待される動作:**
- データを作成
- 作成されたデータを取得
- 内容が一致する

### 5. **境界値での堅牢性（Boundary Robustness）**
極端な値に対してもシステムが適切に動作する性質

```javascript
property: 境界値でもサーバーはクラッシュしない
```

**テストケース:**
- 空文字列
- 極端に長い文字列  
- 最大値・最小値
- NaN、Infinity

### 6. **パフォーマンス特性（Performance Characteristics）**
レスポンス時間が合理的な範囲内にある性質

```javascript
property: レスポンス時間は合理的な範囲内である
```

**期待される動作:**
- 各リクエストが5秒以内に完了
- メモリ使用量が異常に増加しない

## 🔧 プロパティテストの実装パターン

### 1. **ジェネレーター関数**
テストデータを生成する関数

```javascript
const PropertyTestGenerators = {
  validUser: () => ({
    name: faker.person.fullName(),
    email: faker.internet.email(),
    age: faker.number.int({ min: 1, max: 120 })
  }),
  
  boundaryValues: {
    strings: () => ['', 'a', 'a'.repeat(1000)],
    numbers: () => [0, -1, Number.MAX_SAFE_INTEGER, NaN]
  }
};
```

### 2. **プロパティ定義**
システムが満たすべき性質を定義

```javascript
const CommonProperties = {
  validApiResponse: (response) => 
    response && 
    typeof response.status === 'number' &&
    response.status >= 100 && response.status < 600,
    
  idempotent: (operation, input) => {
    const result1 = operation(input);
    const result2 = operation(input);
    return JSON.stringify(result1) === JSON.stringify(result2);
  }
};
```

### 3. **プロパティテスト実行**
定義されたプロパティを多数のケースで検証

```javascript
function runPropertyTest(generator, property, iterations = 100) {
  for (let i = 0; i < iterations; i++) {
    const input = generator();
    const result = property(input);
    // 結果を蓄積・分析
  }
}
```

## 📊 テスト結果の解釈

### 成功率の目安

| プロパティタイプ | 期待成功率 | 許容範囲 |
|----------------|----------|----------|
| べき等性 | 95%以上 | 70%以上 |
| 不変条件 | 90%以上 | 80%以上 |
| 例外安全性 | 98%以上 | 95%以上 |
| データ整合性 | 95%以上 | 80%以上 |
| 境界値堅牢性 | 85%以上 | 70%以上 |

### 失敗の分析

#### **正常な失敗**
- レート制限による一時的な拒否
- バリデーションエラー
- 競合状態による失敗

#### **問題のある失敗**
- サーバークラッシュ（HTTP 5xx）
- データ破損
- メモリリーク

## 🚀 実行方法

### 単独実行
```bash
npm run test:property
```

### 詳細ログ付き実行
```bash
npm test tests/fuzzing/property-based-fuzzing.test.js -- --verbose
```

### 特定のプロパティのみテスト
```bash
npm test -- --testNamePattern="べき等性"
```

## 🛠️ カスタマイズ

### 新しいプロパティの追加

1. **ジェネレーター関数を定義**
```javascript
customGenerator: () => ({
  // カスタムデータ生成ロジック
})
```

2. **プロパティを定義**
```javascript
customProperty: (input) => {
  // 検証したい性質を記述
  return /* boolean */;
}
```

3. **テストケースを追加**
```javascript
test('プロパティ: カスタムプロパティ', () => {
  const result = runPropertyTest(customGenerator, customProperty);
  expect(result.successRate).toBeGreaterThan(0.8);
});
```

### 実行回数の調整

```javascript
// 高速テスト（開発時）
runPropertyTest(generator, property, 20);

// 詳細テスト（CI/CD）
runPropertyTest(generator, property, 100);

// 徹底テスト（リリース前）
runPropertyTest(generator, property, 1000);
```

## 📈 利点

### **バグ発見能力**
- 予期しないエッジケースを発見
- 人間が見落としがちな組み合わせをテスト
- 高い網羅率

### **回帰テスト**
- システム変更時の影響を検出
- プロパティが維持されることを確認
- 長期的な品質保証

### **ドキュメント効果**
- システムの仕様を明確化
- 期待される動作を記述
- チーム間の認識統一

## ⚠️ 注意点

### **実行時間**
- 多数のケースを実行するため時間がかかる
- CI/CDでの実行時間を考慮

### **非決定性**
- ランダム要素により結果が変動
- シード値の固定で再現性を確保

### **プロパティの設計**
- 適切なプロパティの定義が重要
- 過度に厳密すぎると偽陽性
- 緩すぎると問題を見逃す

プロパティベーステストは、従来のテストでは見つけにくいバグを発見し、システムの堅牢性を大幅に向上させる強力な手法です。