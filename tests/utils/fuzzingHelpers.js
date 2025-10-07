const { faker } = require('@faker-js/faker');

/**
 * ランダムな文字列を生成
 */
function generateRandomString(options = {}) {
  const {
    minLength = 1,
    maxLength = 100,
    includeSpecialChars = true,
    includeUnicode = true,
    includeSQL = false,
    includeXSS = false
  } = options;

  const generators = [
    () => faker.string.alpha(faker.number.int({ min: minLength, max: maxLength })),
    () => faker.lorem.words(faker.number.int({ min: 1, max: 10 })),
    () => faker.string.alphanumeric(faker.number.int({ min: minLength, max: maxLength })),
    () => '', // 空文字列
    () => ' '.repeat(faker.number.int({ min: 1, max: 10 })), // スペースのみ
    () => faker.string.alpha(faker.number.int({ min: maxLength, max: maxLength * 2 })) // 長い文字列
  ];

  if (includeSpecialChars) {
    generators.push(
      () => `!@#$%^&*()_+-=[]{}|;':",./<>?`,
      () => `${faker.string.alpha(10)}${faker.string.symbol(5)}`,
      () => faker.string.sample(faker.number.int({ min: minLength, max: maxLength }))
    );
  }

  if (includeUnicode) {
    generators.push(
      () => '🚀🎉💻🔥⚡️🌟',
      () => 'ñáéíóúü',
      () => '中文测试',
      () => 'тест',
      () => 'اختبار'
    );
  }

  if (includeSQL) {
    generators.push(
      () => "'; DROP TABLE users; --",
      () => "' OR '1'='1",
      () => "'; DELETE FROM posts; --",
      () => "UNION SELECT * FROM users",
      () => "1' AND (SELECT COUNT(*) FROM users) > 0 --"
    );
  }

  if (includeXSS) {
    generators.push(
      () => "<script>alert('XSS')</script>",
      () => "javascript:alert('XSS')",
      () => "<img src=x onerror=alert('XSS')>",
      () => "';alert('XSS');//",
      () => "<svg onload=alert('XSS')>"
    );
  }

  const generator = faker.helpers.arrayElement(generators);
  return generator();
}

/**
 * ランダムな数値を生成
 */
function generateRandomNumber(options = {}) {
  const {
    includeNegative = true,
    includeFloat = true,
    includeExtreme = true
  } = options;

  const generators = [
    () => faker.number.int({ min: 0, max: 1000 }),
    () => faker.number.int({ min: 1, max: 100 }),
    () => 0,
    () => 1
  ];

  if (includeNegative) {
    generators.push(
      () => faker.number.int({ min: -1000, max: -1 }),
      () => -1
    );
  }

  if (includeFloat) {
    generators.push(
      () => faker.number.float({ min: 0, max: 1000, fractionDigits: 2 }),
      () => faker.number.float({ min: -1000, max: 1000, fractionDigits: 5 })
    );
  }

  if (includeExtreme) {
    generators.push(
      () => Number.MAX_SAFE_INTEGER,
      () => Number.MIN_SAFE_INTEGER,
      () => Number.POSITIVE_INFINITY,
      () => Number.NEGATIVE_INFINITY,
      () => NaN
    );
  }

  const generator = faker.helpers.arrayElement(generators);
  return generator();
}

/**
 * ランダムなメールアドレスを生成
 */
function generateRandomEmail(options = {}) {
  const { includeMalformed = true } = options;

  const generators = [
    () => faker.internet.email(),
    () => faker.internet.email().toLowerCase(),
    () => faker.internet.email().toUpperCase()
  ];

  if (includeMalformed) {
    generators.push(
      () => 'invalid-email',
      () => 'test@',
      () => '@example.com',
      () => 'test..test@example.com',
      () => 'test@example',
      () => '',
      () => ' ',
      () => 'test@example..com',
      () => generateRandomString({ maxLength: 20 }) + '@' + generateRandomString({ maxLength: 10 })
    );
  }

  const generator = faker.helpers.arrayElement(generators);
  return generator();
}

/**
 * ランダムなオブジェクトを生成
 */
function generateRandomObject(options = {}) {
  const { includeNested = true, maxDepth = 3, currentDepth = 0 } = options;

  if (currentDepth >= maxDepth) {
    return generateRandomString();
  }

  const generators = [
    () => ({}), // 空オブジェクト
    () => null,
    () => undefined,
    () => [],
    () => [generateRandomString(), generateRandomNumber()],
    () => ({
      name: generateRandomString(),
      age: generateRandomNumber(),
      email: generateRandomEmail()
    })
  ];

  if (includeNested && currentDepth < maxDepth) {
    generators.push(() => ({
      nested: generateRandomObject({ ...options, currentDepth: currentDepth + 1 }),
      data: generateRandomString()
    }));
  }

  const generator = faker.helpers.arrayElement(generators);
  return generator();
}

/**
 * ランダムなHTTPヘッダーを生成
 */
function generateRandomHeaders() {
  const headers = {};
  
  const headerGenerators = [
    () => ({ 'Content-Type': faker.helpers.arrayElement([
      'application/json',
      'application/xml',
      'text/plain',
      'text/html',
      'application/x-www-form-urlencoded',
      'multipart/form-data',
      generateRandomString({ maxLength: 50 })
    ])}),
    () => ({ 'User-Agent': faker.helpers.arrayElement([
      faker.internet.userAgent(),
      generateRandomString({ maxLength: 100 }),
      ''
    ])}),
    () => ({ 'Authorization': faker.helpers.arrayElement([
      `Bearer ${faker.string.alphanumeric(32)}`,
      `Basic ${Buffer.from('user:pass').toString('base64')}`,
      generateRandomString({ maxLength: 100 }),
      ''
    ])}),
    () => ({ 'X-Forwarded-For': faker.internet.ip() }),
    () => ({ 'Accept': faker.helpers.arrayElement([
      'application/json',
      '*/*',
      'text/html',
      generateRandomString({ maxLength: 50 })
    ])})
  ];

  // ランダムに1-3個のヘッダーを追加
  const numHeaders = faker.number.int({ min: 0, max: 3 });
  for (let i = 0; i < numHeaders; i++) {
    const generator = faker.helpers.arrayElement(headerGenerators);
    Object.assign(headers, generator());
  }

  return headers;
}

/**
 * ファジングテスト用のペイロードを生成
 */
function generateFuzzingPayloads(basePayload = {}) {
  const payloads = [];
  
  // 基本的な有効なペイロード
  payloads.push(basePayload);
  
  // 各フィールドに対してファジング
  Object.keys(basePayload).forEach(key => {
    // 文字列フィールドのファジング
    if (typeof basePayload[key] === 'string') {
      payloads.push({
        ...basePayload,
        [key]: generateRandomString({ includeSQL: true, includeXSS: true })
      });
      payloads.push({ ...basePayload, [key]: null });
      payloads.push({ ...basePayload, [key]: undefined });
      payloads.push({ ...basePayload, [key]: '' });
      payloads.push({ ...basePayload, [key]: ' '.repeat(1000) }); // 長い文字列
    }
    
    // 数値フィールドのファジング
    if (typeof basePayload[key] === 'number') {
      payloads.push({
        ...basePayload,
        [key]: generateRandomNumber({ includeExtreme: true })
      });
      payloads.push({ ...basePayload, [key]: 'not-a-number' });
      payloads.push({ ...basePayload, [key]: null });
    }
  });
  
  // 追加フィールドのテスト
  payloads.push({
    ...basePayload,
    extraField: generateRandomString(),
    anotherExtra: generateRandomNumber()
  });
  
  // 完全にランダムなペイロード
  payloads.push(generateRandomObject());
  
  // 空のペイロード
  payloads.push({});
  payloads.push(null);
  payloads.push(undefined);
  
  return payloads;
}

module.exports = {
  generateRandomString,
  generateRandomNumber,
  generateRandomEmail,
  generateRandomObject,
  generateRandomHeaders,
  generateFuzzingPayloads
};