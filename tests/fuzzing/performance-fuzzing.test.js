const request = require('supertest');
const { app } = require('../../src/server');
const {
  generateRandomString,
  generateRandomNumber,
  generateFuzzingPayloads
} = require('../utils/fuzzingHelpers');

describe('Performance Fuzzing Tests', () => {
  describe('レスポンス時間テスト', () => {
    test('各エンドポイントのレスポンス時間測定', async () => {
      const endpoints = [
        { method: 'GET', path: '/health' },
        { method: 'GET', path: '/api/users' },
        { method: 'GET', path: '/api/posts' },
        { method: 'GET', path: '/api/search?query=test' }
      ];

      const results = [];

      for (const endpoint of endpoints) {
        const iterations = 20;
        const responseTimes = [];

        for (let i = 0; i < iterations; i++) {
          const startTime = Date.now();
          
          let response;
          if (endpoint.method === 'GET') {
            response = await request(app).get(endpoint.path);
          }
          
          const endTime = Date.now();
          const responseTime = endTime - startTime;
          
          responseTimes.push(responseTime);
          
          // 基本的なレスポンス検証
          expect(response.status).toBeLessThan(500);
        }

        const avgResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
        const maxResponseTime = Math.max(...responseTimes);
        const minResponseTime = Math.min(...responseTimes);

        results.push({
          endpoint: `${endpoint.method} ${endpoint.path}`,
          avgResponseTime,
          maxResponseTime,
          minResponseTime,
          responseTimes
        });

        // パフォーマンス基準
        expect(avgResponseTime).toBeLessThan(1000); // 平均1秒以内
        expect(maxResponseTime).toBeLessThan(2000); // 最大2秒以内
      }

      // 結果をログ出力
      console.log('\nPerformance Test Results:');
      results.forEach(result => {
        console.log(`${result.endpoint}:`);
        console.log(`  Avg: ${result.avgResponseTime.toFixed(2)}ms`);
        console.log(`  Max: ${result.maxResponseTime}ms`);
        console.log(`  Min: ${result.minResponseTime}ms`);
      });
    });
  });

  describe('同時接続テスト', () => {
    test('大量の同時リクエストでの安定性', async () => {
      const concurrentRequests = 50;
      const promises = [];

      // 同時に大量のリクエストを作成
      for (let i = 0; i < concurrentRequests; i++) {
        const promise = request(app)
          .get('/api/users')
          .query({
            page: generateRandomNumber({ includeNegative: false }) % 10 + 1,
            limit: generateRandomNumber({ includeNegative: false }) % 20 + 1
          });
        promises.push(promise);
      }

      const startTime = Date.now();
      const responses = await Promise.all(promises);
      const endTime = Date.now();
      const totalTime = endTime - startTime;

      // 結果分析
      const successfulResponses = responses.filter(r => r.status === 200);
      const errorResponses = responses.filter(r => r.status >= 400);
      const serverErrors = responses.filter(r => r.status >= 500);

      console.log(`\nConcurrency Test Results:`);
      console.log(`Total requests: ${concurrentRequests}`);
      console.log(`Successful: ${successfulResponses.length}`);
      console.log(`Client errors (4xx): ${errorResponses.length - serverErrors.length}`);
      console.log(`Server errors (5xx): ${serverErrors.length}`);
      console.log(`Total time: ${totalTime}ms`);
      console.log(`Avg time per request: ${(totalTime / concurrentRequests).toFixed(2)}ms`);

      // アサーション
      expect(serverErrors.length).toBe(0); // サーバーエラーは0であるべき
      expect(successfulResponses.length).toBeGreaterThan(concurrentRequests * 0.8); // 80%以上成功
      expect(totalTime).toBeLessThan(10000); // 10秒以内で完了
    });
  });

  describe('メモリ使用量テスト', () => {
    test('大量データ処理でのメモリリーク検証', async () => {
      const iterations = 100;
      
      for (let i = 0; i < iterations; i++) {
        // 大きなペイロードでユーザー作成
        const largePayload = {
          name: generateRandomString({ minLength: 1000, maxLength: 5000 }),
          email: `test${i}@example.com`,
          age: generateRandomNumber({ includeNegative: false }) % 100
        };

        const response = await request(app)
          .post('/api/users')
          .send(largePayload);

        // 基本的なレスポンス検証
        expect([200, 201, 400, 409]).toContain(response.status);

        // 定期的にメモリ使用量をチェック
        if (i % 20 === 0) {
          const memUsage = process.memoryUsage();
          console.log(`Iteration ${i}: Memory usage - RSS: ${(memUsage.rss / 1024 / 1024).toFixed(2)}MB, Heap: ${(memUsage.heapUsed / 1024 / 1024).toFixed(2)}MB`);
          
          // メモリ使用量が異常に増加していないかチェック
          expect(memUsage.heapUsed).toBeLessThan(100 * 1024 * 1024); // 100MB以内
        }
      }
    });
  });

  describe('エッジケースストレステスト', () => {
    test('極端なクエリパラメータでの処理', async () => {
      const extremeQueries = [
        { page: 0, limit: 0 },
        { page: -1, limit: -1 },
        { page: 999999, limit: 999999 },
        { page: 1.5, limit: 2.7 },
        { page: 'invalid', limit: 'invalid' },
        { page: null, limit: null },
        { search: generateRandomString({ minLength: 10000, maxLength: 10000 }) }
      ];

      for (const query of extremeQueries) {
        const response = await request(app)
          .get('/api/users')
          .query(query);

        // サーバーエラーを起こさない
        expect(response.status).toBeLessThan(500);
        
        // レスポンスタイムが合理的
        expect(response.duration || 0).toBeLessThan(5000);
      }
    });

    test('大量のネストしたオブジェクトでの処理', async () => {
      const createNestedObject = (depth) => {
        if (depth === 0) return generateRandomString();
        return {
          level: depth,
          data: generateRandomString(),
          nested: createNestedObject(depth - 1)
        };
      };

      const deeplyNestedPayload = {
        name: 'Test User',
        email: 'test@example.com',
        metadata: createNestedObject(20), // 20レベルの深いネスト
        age: 25
      };

      const response = await request(app)
        .post('/api/users')
        .send(deeplyNestedPayload);

      // 深いネストでもサーバーエラーを起こさない
      expect(response.status).toBeLessThan(500);
    });
  });

  describe('データベース負荷テスト', () => {
    test('大量のユーザー作成と検索', async () => {
      const userCount = 50;
      const createdUsers = [];

      // 大量のユーザーを作成
      for (let i = 0; i < userCount; i++) {
        const user = {
          name: `User ${i} ${generateRandomString({ maxLength: 20 })}`,
          email: `user${i}_${Date.now()}@example.com`,
          age: generateRandomNumber({ includeNegative: false }) % 80 + 18
        };

        const response = await request(app)
          .post('/api/users')
          .send(user);

        if (response.status === 201) {
          createdUsers.push(response.body);
        }
      }

      console.log(`Created ${createdUsers.length} users for load testing`);

      // 作成したユーザーをランダムに検索
      const searchPromises = [];
      for (let i = 0; i < 20; i++) {
        const randomUser = createdUsers[Math.floor(Math.random() * createdUsers.length)];
        if (randomUser) {
          searchPromises.push(
            request(app)
              .get('/api/users')
              .query({ search: randomUser.name.split(' ')[0] })
          );
        }
      }

      const searchResponses = await Promise.all(searchPromises);
      
      // 検索が適切に動作する
      searchResponses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('users');
      });

      // クリーンアップ - 作成したユーザーを削除
      const deletePromises = createdUsers.map(user =>
        request(app).delete(`/api/users/${user.id}`)
      );
      
      await Promise.all(deletePromises);
    });
  });

  describe('レート制限境界テスト', () => {
    test('レート制限の境界値でのテスト', async () => {
      const rateLimitRequests = 100; // レート制限よりも多いリクエスト
      const promises = [];

      for (let i = 0; i < rateLimitRequests; i++) {
        promises.push(
          request(app)
            .get('/api/users')
            .set('X-Forwarded-For', `192.168.1.${i % 255}`) // 異なるIPアドレスをシミュレート
        );
      }

      const responses = await Promise.all(promises.map(p => 
        p.catch(err => ({ status: 500, error: err.message }))
      ));

      const successfulRequests = responses.filter(r => r.status === 200);
      const rateLimitedRequests = responses.filter(r => r.status === 429);
      const errorRequests = responses.filter(r => r.status >= 500);

      console.log(`\nRate Limiting Test Results:`);
      console.log(`Total requests: ${rateLimitRequests}`);
      console.log(`Successful: ${successfulRequests.length}`);
      console.log(`Rate limited (429): ${rateLimitedRequests.length}`);
      console.log(`Server errors: ${errorRequests.length}`);

      // レート制限が適切に動作する
      expect(errorRequests.length).toBe(0);
      expect(successfulRequests.length + rateLimitedRequests.length).toBe(rateLimitRequests);
    });
  });
});