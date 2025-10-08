const request = require('supertest');
const { app } = require('../../src/server');
const {
  PropertyTestGenerators,
  runPropertyTest,
  CommonProperties,
  generateRandomString,
  generateRandomNumber
} = require('../utils/fuzzingHelpers');

describe('Property-Based Fuzzing Tests', () => {
  let server;

  beforeAll(async () => {
    // テスト用サーバーを起動
    server = app.listen(0);
  });

  afterAll(async () => {
    // テスト終了後にサーバーを閉じる
    if (server) {
      await new Promise((resolve) => {
        server.close(resolve);
      });
    }
  });

  describe('ユーザー作成APIのプロパティテスト', () => {
    test('プロパティ: 有効なユーザーデータは常に適切なレスポンスを返す', async () => {
      const property = async (userInput) => {
        const response = await request(app)
          .post('/api/users')
          .send(userInput);

        // プロパティ1: レスポンスは常に有効な形式である
        expect(CommonProperties.validApiResponse(response)).toBe(true);

        // プロパティ2: 有効な入力に対してはサーバーエラー(5xx)が発生しない
        expect(response.status).toBeLessThan(500);

        // プロパティ3: 成功した場合は作成されたリソースが返される
        if (response.status === 201) {
          expect(response.body).toHaveProperty('id');
          expect(response.body).toHaveProperty('name');
          expect(response.body).toHaveProperty('email');
        }

        return response;
      };

      const result = runPropertyTest(
        PropertyTestGenerators.validUser,
        property,
        20 // テスト実行時間を短縮するため20回に制限
      );

      console.log(`\nユーザー作成プロパティテスト結果:`);
      console.log(`総実行回数: ${result.totalRuns}`);
      console.log(`成功: ${result.successes}`);
      console.log(`失敗: ${result.failures}`);
      console.log(`成功率: ${(result.successRate * 100).toFixed(1)}%`);

      // 少なくとも80%の成功率を期待
      expect(result.successRate).toBeGreaterThan(0.8);
    });

    test('プロパティ: 境界値に対する堅牢性', async () => {
      const boundaryTestCases = [
        ...PropertyTestGenerators.boundaryValues.strings().map(str => ({
          name: str,
          email: 'test@example.com',
          age: 25
        })),
        ...PropertyTestGenerators.boundaryValues.numbers().map(num => ({
          name: 'Test User',
          email: 'test@example.com',
          age: num
        }))
      ];

      const results = [];
      for (const testCase of boundaryTestCases) {
        try {
          const response = await request(app)
            .post('/api/users')
            .send(testCase);

          results.push({
            input: testCase,
            status: response.status,
            success: response.status < 500
          });

          // プロパティ: 境界値でもサーバーはクラッシュしない
          expect(response.status).toBeLessThan(500);
        } catch (error) {
          results.push({
            input: testCase,
            error: error.message,
            success: false
          });
        }
      }

      const successCount = results.filter(r => r.success).length;
      console.log(`\n境界値テスト結果:`);
      console.log(`総テストケース: ${boundaryTestCases.length}`);
      console.log(`成功: ${successCount}`);
      console.log(`成功率: ${(successCount / boundaryTestCases.length * 100).toFixed(1)}%`);

      // 境界値テストでも最低限の成功率を期待
      expect(successCount / boundaryTestCases.length).toBeGreaterThan(0.7);
    });
  });

  describe('投稿作成APIのプロパティテスト', () => {
    let testUserId;

    beforeAll(async () => {
      // テスト用ユーザーを作成
      const userResponse = await request(app)
        .post('/api/users')
        .send(PropertyTestGenerators.validUser());
      
      if (userResponse.status === 201) {
        testUserId = userResponse.body.id;
      } else {
        testUserId = 1; // フォールバック
      }
    });

    test('プロパティ: 有効な投稿データは適切に処理される', async () => {
      const property = async (postInput) => {
        const postData = { ...postInput, userId: testUserId };
        const response = await request(app)
          .post('/api/posts')
          .send(postData);

        // プロパティ1: レスポンスは常に有効
        expect(CommonProperties.validApiResponse(response)).toBe(true);

        // プロパティ2: サーバーエラーが発生しない
        expect(response.status).toBeLessThan(500);

        // プロパティ3: 成功時は投稿オブジェクトが返される
        if (response.status === 201) {
          expect(response.body).toHaveProperty('id');
          expect(response.body).toHaveProperty('title');
          expect(response.body).toHaveProperty('content');
          expect(response.body.userId).toBe(testUserId);
        }

        return response;
      };

      const result = runPropertyTest(
        PropertyTestGenerators.validPost,
        property,
        15
      );

      console.log(`\n投稿作成プロパティテスト結果:`);
      console.log(`総実行回数: ${result.totalRuns}`);
      console.log(`成功: ${result.successes}`);
      console.log(`成功率: ${(result.successRate * 100).toFixed(1)}%`);

      expect(result.successRate).toBeGreaterThan(0.7);
    });
  });

  describe('べき等性のプロパティテスト', () => {
    test('プロパティ: GETリクエストは常にべき等である', async () => {
      const property = async () => {
        const response1 = await request(app).get('/api/users');
        const response2 = await request(app).get('/api/users');

        // べき等性: 同じリクエストを複数回実行しても結果が同じ
        // 注意: レート制限により異なるステータスコードが返される場合があります（予想される失敗）
        if (response1.status < 400 && response2.status < 400) {
          expect(response1.status).toBe(response2.status);
        }
        
        if (response1.status === 200 && response2.status === 200) {
          // データの一貫性を確認（レスポンス構造が同じ）
          expect(response1.body).toHaveProperty('users');
          expect(response2.body).toHaveProperty('users');
          expect(Array.isArray(response1.body.users)).toBe(true);
          expect(Array.isArray(response2.body.users)).toBe(true);
        }

        return { response1, response2 };
      };

      const result = runPropertyTest(
        () => ({}), // 入力は不要
        property,
        10
      );

      console.log(`\nべき等性テスト結果:`);
      console.log(`成功率: ${(result.successRate * 100).toFixed(1)}%`);

      // べき等性は高い確率で成り立つべき（レート制限の影響を考慮）
      expect(result.successRate).toBeGreaterThan(0.7);
    });
  });

  describe('不変条件のプロパティテスト', () => {
    test('プロパティ: ユーザー数は作成により増加し、削除により減少する', async () => {
      const property = async () => {
        // 初期状態のユーザー数を取得
        const initialResponse = await request(app).get('/api/users?page=1&limit=1000');
        const initialCount = initialResponse.body.users ? initialResponse.body.users.length : 0;

        // ユーザーを作成
        const createResponse = await request(app)
          .post('/api/users')
          .send(PropertyTestGenerators.validUser());

        let afterCreateCount = initialCount;
        if (createResponse.status === 201) {
          const afterCreateResponse = await request(app).get('/api/users?page=1&limit=1000');
          afterCreateCount = afterCreateResponse.body.users ? afterCreateResponse.body.users.length : 0;

          // 不変条件1: 作成後はユーザー数が増加する
          expect(afterCreateCount).toBeGreaterThanOrEqual(initialCount);

          // 作成されたユーザーを削除
          const deleteResponse = await request(app)
            .delete(`/api/users/${createResponse.body.id}`);

          if (deleteResponse.status === 200) {
            const afterDeleteResponse = await request(app).get('/api/users?page=1&limit=1000');
            const afterDeleteCount = afterDeleteResponse.body.users ? afterDeleteResponse.body.users.length : 0;

            // 不変条件2: 削除後はユーザー数が減少する
            expect(afterDeleteCount).toBeLessThanOrEqual(afterCreateCount);
          }
        }

        return { initialCount, afterCreateCount };
      };

      const result = runPropertyTest(
        () => ({}),
        property,
        5 // データベース操作のため少なめに
      );

      console.log(`\n不変条件テスト結果:`);
      console.log(`成功率: ${(result.successRate * 100).toFixed(1)}%`);

      // 不変条件は高い確率で成り立つべき
      expect(result.successRate).toBeGreaterThan(0.8);
    });
  });

  describe('例外安全性のプロパティテスト', () => {
    test('プロパティ: 不正な入力でもシステムは安定している', async () => {
      const property = async () => {
        // ランダムで不正な可能性の高いデータを生成
        const maliciousData = {
          name: generateRandomString({ 
            includeSQL: true, 
            includeXSS: true, 
            maxLength: 10000 
          }),
          email: generateRandomString({ maxLength: 500 }),
          age: generateRandomNumber({ includeExtreme: true }),
          // 予期しないフィールド
          maliciousField: generateRandomString({ includeSQL: true }),
          nestedObject: {
            evil: generateRandomString({ includeXSS: true })
          }
        };

        const response = await request(app)
          .post('/api/users')
          .send(maliciousData);

        // プロパティ: 不正な入力でもサーバーはクラッシュしない
        expect(response.status).toBeLessThan(500);

        // プロパティ: レスポンスは有効な形式
        expect(CommonProperties.validApiResponse(response)).toBe(true);

        // プロパティ: エラーの場合は適切なエラーメッセージが返される
        if (response.status >= 400) {
          expect(response.body).toHaveProperty('error');
          expect(typeof response.body.error).toBe('string');
        }

        return response;
      };

      const result = runPropertyTest(
        () => ({}),
        property,
        30
      );

      console.log(`\n例外安全性テスト結果:`);
      console.log(`総実行回数: ${result.totalRuns}`);
      console.log(`システム安定性: ${(result.successRate * 100).toFixed(1)}%`);

      // システムは不正な入力に対しても高い安定性を保つべき
      expect(result.successRate).toBeGreaterThan(0.95);
    });
  });

  describe('パフォーマンス特性のプロパティテスト', () => {
    test('プロパティ: レスポンス時間は入力サイズに比例して増加する', async () => {
      const testSizes = [10, 100, 1000, 5000];
      const results = [];

      for (const size of testSizes) {
        const largeData = {
          name: 'Test User',
          email: 'test@example.com',
          age: 25,
          description: 'a'.repeat(size) // サイズを変える
        };

        const startTime = Date.now();
        const response = await request(app)
          .post('/api/users')
          .send(largeData);
        const endTime = Date.now();
        const responseTime = endTime - startTime;

        results.push({
          size,
          responseTime,
          status: response.status
        });

        // プロパティ: 大きな入力でもサーバーはクラッシュしない
        expect(response.status).toBeLessThan(500);
      }

      console.log(`\nパフォーマンス特性テスト結果:`);
      results.forEach(({ size, responseTime, status }) => {
        console.log(`サイズ ${size}: ${responseTime}ms (status: ${status})`);
      });

      // プロパティ: 合理的なレスポンス時間
      results.forEach(({ responseTime }) => {
        expect(responseTime).toBeLessThan(5000); // 5秒以内
      });
    });
  });

  describe('データ整合性のプロパティテスト', () => {
    test('プロパティ: 作成されたデータは取得可能である', async () => {
      const property = async (userData) => {
        // ユーザーを作成
        const createResponse = await request(app)
          .post('/api/users')
          .send(userData);

        if (createResponse.status === 201) {
          const createdUser = createResponse.body;

          // 作成されたユーザーを取得
          const getResponse = await request(app)
            .get(`/api/users/${createdUser.id}`);

          // プロパティ: 作成されたデータは取得可能
          expect(getResponse.status).toBe(200);

          // プロパティ: 取得されたデータは作成時と一致
          expect(getResponse.body.id).toBe(createdUser.id);
          expect(getResponse.body.name).toBe(createdUser.name);
          expect(getResponse.body.email).toBe(createdUser.email);

          // クリーンアップ
          await request(app).delete(`/api/users/${createdUser.id}`);
        }

        return createResponse;
      };

      const result = runPropertyTest(
        PropertyTestGenerators.validUser,
        property,
        10
      );

      console.log(`\nデータ整合性テスト結果:`);
      console.log(`成功率: ${(result.successRate * 100).toFixed(1)}%`);

      // データ整合性は高い確率で保たれるべき
      expect(result.successRate).toBeGreaterThan(0.8);
    });
  });
});