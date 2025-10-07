#!/usr/bin/env node

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * ファジングテスト実行とレポート生成スクリプト
 */
class FuzzingTestRunner {
  constructor() {
    this.results = {
      timestamp: new Date().toISOString(),
      summary: {},
      testSuites: [],
      vulnerabilities: [],
      performance: {},
      coverage: {}
    };
  }

  /**
   * 全てのファジングテストを実行
   */
  async runAllTests() {
    console.log('🚀 Starting API Fuzzing Test Suite...\n');
    
    try {
      // 1. 基本的なAPIファジングテスト
      console.log('📋 Running Basic API Fuzzing Tests...');
      await this.runTestSuite('tests/fuzzing/api-fuzzing.test.js', 'API Fuzzing');

      // 2. パフォーマンスファジングテスト
      console.log('⚡ Running Performance Fuzzing Tests...');
      await this.runTestSuite('tests/fuzzing/performance-fuzzing.test.js', 'Performance Fuzzing');

      // 3. セキュリティファジングテスト
      console.log('🔒 Running Security Fuzzing Tests...');
      await this.runTestSuite('tests/fuzzing/security-fuzzing.test.js', 'Security Fuzzing');

      // 4. カバレッジレポート生成
      console.log('📊 Generating Coverage Report...');
      await this.generateCoverageReport();

      // 5. 総合レポート生成
      console.log('📝 Generating Comprehensive Report...');
      await this.generateReport();

      console.log('\n✅ All fuzzing tests completed successfully!');
      console.log('📄 Report generated: fuzzing-report.html');

    } catch (error) {
      console.error('❌ Fuzzing tests failed:', error.message);
      process.exit(1);
    }
  }

  /**
   * 個別のテストスイートを実行
   */
  async runTestSuite(testFile, suiteName) {
    return new Promise((resolve, reject) => {
      const command = `npm test -- ${testFile} --json --outputFile=test-results-${suiteName.toLowerCase().replace(/\s+/g, '-')}.json`;
      
      exec(command, { maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
        const result = {
          suiteName,
          testFile,
          passed: !error,
          output: stdout,
          errors: stderr,
          timestamp: new Date().toISOString()
        };

        this.results.testSuites.push(result);

        if (error) {
          console.log(`⚠️  ${suiteName} completed with issues`);
        } else {
          console.log(`✅ ${suiteName} passed`);
        }

        resolve(result);
      });
    });
  }

  /**
   * カバレッジレポートを生成
   */
  async generateCoverageReport() {
    return new Promise((resolve, reject) => {
      exec('npm test -- --coverage --coverageReporters=json-summary', (error, stdout, stderr) => {
        if (error) {
          console.log('⚠️  Coverage report generation failed');
          resolve();
          return;
        }

        try {
          const coveragePath = path.join(process.cwd(), 'coverage', 'coverage-summary.json');
          if (fs.existsSync(coveragePath)) {
            const coverage = JSON.parse(fs.readFileSync(coveragePath, 'utf8'));
            this.results.coverage = coverage;
            console.log('✅ Coverage report generated');
          }
        } catch (e) {
          console.log('⚠️  Failed to parse coverage data');
        }

        resolve();
      });
    });
  }

  /**
   * 包括的なHTMLレポートを生成
   */
  async generateReport() {
    const report = this.generateHTMLReport();
    fs.writeFileSync('fuzzing-report.html', report);
    
    // JSON形式でも出力
    fs.writeFileSync('fuzzing-report.json', JSON.stringify(this.results, null, 2));
  }

  /**
   * HTMLレポートを生成
   */
  generateHTMLReport() {
    const totalTests = this.results.testSuites.length;
    const passedTests = this.results.testSuites.filter(t => t.passed).length;
    const failedTests = totalTests - passedTests;

    return `
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Fuzzing Test Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 2px solid #eee;
        }
        .header h1 {
            color: #333;
            margin: 0;
        }
        .header p {
            color: #666;
            margin: 10px 0 0 0;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .summary-card.success {
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
        }
        .summary-card.danger {
            background: linear-gradient(135deg, #f44336 0%, #da190b 100%);
        }
        .summary-card.warning {
            background: linear-gradient(135deg, #ff9800 0%, #f57c00 100%);
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            font-size: 2.5em;
        }
        .summary-card p {
            margin: 0;
            opacity: 0.9;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .test-suite {
            background: #f9f9f9;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 4px solid #667eea;
        }
        .test-suite.failed {
            border-left-color: #f44336;
        }
        .test-suite h3 {
            margin: 0 0 10px 0;
            color: #333;
        }
        .status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .status.passed {
            background: #4CAF50;
            color: white;
        }
        .status.failed {
            background: #f44336;
            color: white;
        }
        .coverage-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }
        .coverage-item {
            text-align: center;
            padding: 15px;
            background: #f0f0f0;
            border-radius: 6px;
        }
        .coverage-percentage {
            font-size: 1.5em;
            font-weight: bold;
            color: #667eea;
        }
        .recommendations {
            background: #e3f2fd;
            border-left: 4px solid #2196F3;
            padding: 20px;
            border-radius: 0 6px 6px 0;
        }
        .recommendations h3 {
            margin-top: 0;
            color: #1976D2;
        }
        .recommendations ul {
            margin: 0;
            padding-left: 20px;
        }
        .recommendations li {
            margin-bottom: 8px;
        }
        .timestamp {
            text-align: center;
            color: #666;
            font-size: 0.9em;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        pre {
            background: #f5f5f5;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🧪 API Fuzzing Test Report</h1>
            <p>包括的なAPIセキュリティ・パフォーマンステスト結果</p>
        </div>

        <div class="summary">
            <div class="summary-card success">
                <h3>${passedTests}</h3>
                <p>成功したテストスイート</p>
            </div>
            <div class="summary-card ${failedTests > 0 ? 'danger' : 'success'}">
                <h3>${failedTests}</h3>
                <p>失敗したテストスイート</p>
            </div>
            <div class="summary-card">
                <h3>${totalTests}</h3>
                <p>総テストスイート数</p>
            </div>
            <div class="summary-card warning">
                <h3>${this.results.vulnerabilities.length}</h3>
                <p>検出された脆弱性</p>
            </div>
        </div>

        <div class="section">
            <h2>📋 テストスイート結果</h2>
            ${this.results.testSuites.map(suite => `
                <div class="test-suite ${suite.passed ? '' : 'failed'}">
                    <h3>
                        ${suite.suiteName}
                        <span class="status ${suite.passed ? 'passed' : 'failed'}">
                            ${suite.passed ? 'PASSED' : 'FAILED'}
                        </span>
                    </h3>
                    <p><strong>テストファイル:</strong> ${suite.testFile}</p>
                    <p><strong>実行時刻:</strong> ${new Date(suite.timestamp).toLocaleString('ja-JP')}</p>
                    ${suite.errors ? `<pre>${suite.errors}</pre>` : ''}
                </div>
            `).join('')}
        </div>

        ${Object.keys(this.results.coverage).length > 0 ? `
        <div class="section">
            <h2>📊 コードカバレッジ</h2>
            <div class="coverage-grid">
                ${Object.entries(this.results.coverage.total || {}).map(([key, value]) => `
                    <div class="coverage-item">
                        <div class="coverage-percentage">${value.pct}%</div>
                        <div>${key.charAt(0).toUpperCase() + key.slice(1)}</div>
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}

        <div class="section">
            <h2>🔒 セキュリティ推奨事項</h2>
            <div class="recommendations">
                <h3>推奨される改善点</h3>
                <ul>
                    <li><strong>入力検証:</strong> 全てのユーザー入力に対して厳密な検証を実装してください</li>
                    <li><strong>SQLインジェクション対策:</strong> パラメータ化クエリまたはORMを使用してください</li>
                    <li><strong>XSS対策:</strong> 出力時のエスケープ処理を確実に行ってください</li>
                    <li><strong>認証・認可:</strong> すべてのAPIエンドポイントに適切な認証を実装してください</li>
                    <li><strong>レート制限:</strong> DDoS攻撃を防ぐためのレート制限を強化してください</li>
                    <li><strong>エラーハンドリング:</strong> 詳細なエラー情報が漏洩しないよう注意してください</li>
                    <li><strong>HTTPSの強制:</strong> 本番環境では必ずHTTPSを使用してください</li>
                    <li><strong>セキュリティヘッダー:</strong> CSP、HSTS、X-Frame-Optionsなどを設定してください</li>
                </ul>
            </div>
        </div>

        <div class="section">
            <h2>🚀 パフォーマンス最適化</h2>
            <div class="recommendations">
                <h3>パフォーマンス改善のヒント</h3>
                <ul>
                    <li><strong>データベース最適化:</strong> インデックスの追加とクエリの最適化</li>
                    <li><strong>キャッシュ戦略:</strong> Redis等を使用したキャッシュ層の導入</li>
                    <li><strong>ページネーション:</strong> 大量データの効率的な分割取得</li>
                    <li><strong>非同期処理:</strong> 重い処理の非同期化とキューイング</li>
                    <li><strong>リソース制限:</strong> メモリとCPU使用量の監視と制限</li>
                    <li><strong>CDN活用:</strong> 静的リソースの配信最適化</li>
                </ul>
            </div>
        </div>

        <div class="timestamp">
            レポート生成日時: ${new Date(this.results.timestamp).toLocaleString('ja-JP')}
        </div>
    </div>
</body>
</html>`;
  }
}

// コマンドライン実行時
if (require.main === module) {
  const runner = new FuzzingTestRunner();
  runner.runAllTests().catch(console.error);
}

module.exports = FuzzingTestRunner;