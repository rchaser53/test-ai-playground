#!/usr/bin/env node

/**
 * 簡易ファジングテスト実行スクリプト
 * 各テストファイルを個別に実行してプロセスの終了を確実にする
 */

const { spawn } = require('child_process');
const path = require('path');

const testFiles = [
  'tests/fuzzing/api-fuzzing.test.js',
  'tests/fuzzing/performance-fuzzing.test.js',
  'tests/fuzzing/security-fuzzing.test.js',
  'tests/fuzzing/property-based-fuzzing.test.js'
];

async function runTest(testFile) {
  return new Promise((resolve) => {
    console.log(`\n🧪 Running: ${testFile}`);
    console.log('=' .repeat(50));
    
    const child = spawn('npm', ['test', testFile], {
      stdio: 'inherit',
      env: { ...process.env, NODE_ENV: 'test' }
    });

    child.on('close', (code) => {
      console.log(`\n✅ Test completed: ${testFile} (exit code: ${code})`);
      resolve(code);
    });

    child.on('error', (error) => {
      console.error(`❌ Error running ${testFile}:`, error);
      resolve(1);
    });
  });
}

async function runAllTests() {
  console.log('🚀 Starting Fuzzing Test Suite...\n');
  
  const results = [];
  
  for (const testFile of testFiles) {
    const exitCode = await runTest(testFile);
    results.push({ testFile, exitCode });
    
    // 少し待機してプロセスが完全に終了するのを確認
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  console.log('\n📊 Test Results Summary:');
  console.log('=' .repeat(50));
  
  let totalPassed = 0;
  results.forEach(({ testFile, exitCode }) => {
    const status = exitCode === 0 ? '✅ PASSED' : '❌ FAILED';
    console.log(`${status} ${testFile}`);
    if (exitCode === 0) totalPassed++;
  });
  
  console.log(`\nTotal: ${results.length}, Passed: ${totalPassed}, Failed: ${results.length - totalPassed}`);
  
  if (totalPassed === results.length) {
    console.log('🎉 All tests passed!');
    process.exit(0);
  } else {
    console.log('⚠️  Some tests failed, but processes exited correctly.');
    process.exit(1);
  }
}

// スクリプト実行
if (require.main === module) {
  runAllTests().catch(console.error);
}