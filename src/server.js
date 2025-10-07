const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// プロキシの信頼設定（テスト環境用）
app.set('trust proxy', 1);

// セキュリティとミドルウェア
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// レート制限
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15分
  max: 100 // リクエスト数制限
});
app.use('/api/', limiter);

// インメモリデータストア（テスト用）
let users = [
  { id: 1, name: 'John Doe', email: 'john@example.com', age: 30 },
  { id: 2, name: 'Jane Smith', email: 'jane@example.com', age: 25 }
];

let posts = [
  { id: 1, title: 'First Post', content: 'Hello World', userId: 1 },
  { id: 2, title: 'Second Post', content: 'Node.js is awesome', userId: 2 }
];

// ヘルスチェック
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ユーザー関連API
app.get('/api/users', (req, res) => {
  const { page = 1, limit = 10, search } = req.query;
  let filteredUsers = users;
  
  if (search) {
    filteredUsers = users.filter(user => 
      user.name.toLowerCase().includes(search.toLowerCase()) ||
      user.email.toLowerCase().includes(search.toLowerCase())
    );
  }
  
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;
  const paginatedUsers = filteredUsers.slice(startIndex, endIndex);
  
  res.json({
    users: paginatedUsers,
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total: filteredUsers.length,
      pages: Math.ceil(filteredUsers.length / limit)
    }
  });
});

app.get('/api/users/:id', (req, res) => {
  const id = parseInt(req.params.id);
  
  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  
  const user = users.find(u => u.id === id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  res.json(user);
});

app.post('/api/users', (req, res) => {
  const { name, email, age } = req.body;
  
  // バリデーション
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ error: 'Name is required and must be a non-empty string' });
  }
  
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email is required' });
  }
  
  if (age !== undefined && (typeof age !== 'number' || age < 0 || age > 150)) {
    return res.status(400).json({ error: 'Age must be a number between 0 and 150' });
  }
  
  // 重複チェック
  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    return res.status(409).json({ error: 'User with this email already exists' });
  }
  
  const newUser = {
    id: Math.max(...users.map(u => u.id), 0) + 1,
    name: name.trim(),
    email: email.toLowerCase(),
    age: age || null
  };
  
  users.push(newUser);
  res.status(201).json(newUser);
});

app.put('/api/users/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const { name, email, age } = req.body;
  
  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  
  const userIndex = users.findIndex(u => u.id === id);
  if (userIndex === -1) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // バリデーション（部分更新対応）
  if (name !== undefined && (typeof name !== 'string' || name.trim().length === 0)) {
    return res.status(400).json({ error: 'Name must be a non-empty string' });
  }
  
  if (email !== undefined && (typeof email !== 'string' || !email.includes('@'))) {
    return res.status(400).json({ error: 'Valid email is required' });
  }
  
  if (age !== undefined && (typeof age !== 'number' || age < 0 || age > 150)) {
    return res.status(400).json({ error: 'Age must be a number between 0 and 150' });
  }
  
  // 更新
  if (name !== undefined) users[userIndex].name = name.trim();
  if (email !== undefined) users[userIndex].email = email.toLowerCase();
  if (age !== undefined) users[userIndex].age = age;
  
  res.json(users[userIndex]);
});

app.delete('/api/users/:id', (req, res) => {
  const id = parseInt(req.params.id);
  
  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  
  const userIndex = users.findIndex(u => u.id === id);
  if (userIndex === -1) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const deletedUser = users.splice(userIndex, 1)[0];
  res.json({ message: 'User deleted successfully', user: deletedUser });
});

// 投稿関連API
app.get('/api/posts', (req, res) => {
  const { userId } = req.query;
  let filteredPosts = posts;
  
  if (userId) {
    const userIdNum = parseInt(userId);
    if (!isNaN(userIdNum)) {
      filteredPosts = posts.filter(p => p.userId === userIdNum);
    }
  }
  
  res.json(filteredPosts);
});

app.post('/api/posts', (req, res) => {
  const { title, content, userId } = req.body;
  
  if (!title || typeof title !== 'string' || title.trim().length === 0) {
    return res.status(400).json({ error: 'Title is required' });
  }
  
  if (!content || typeof content !== 'string' || content.trim().length === 0) {
    return res.status(400).json({ error: 'Content is required' });
  }
  
  if (!userId || typeof userId !== 'number') {
    return res.status(400).json({ error: 'Valid userId is required' });
  }
  
  // ユーザー存在チェック
  const user = users.find(u => u.id === userId);
  if (!user) {
    return res.status(400).json({ error: 'User does not exist' });
  }
  
  const newPost = {
    id: Math.max(...posts.map(p => p.id), 0) + 1,
    title: title.trim(),
    content: content.trim(),
    userId: userId
  };
  
  posts.push(newPost);
  res.status(201).json(newPost);
});

// ファイルアップロードエンドポイント（脆弱性テスト用）
app.post('/api/upload', (req, res) => {
  const { filename, content } = req.body;
  
  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'Filename is required' });
  }
  
  // 危険なファイル名パターンをチェック（意図的に不完全）
  if (filename.includes('..') || filename.includes('/')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  res.json({
    message: 'File uploaded successfully',
    filename: filename,
    size: content ? content.length : 0
  });
});

// SQLインジェクション風エンドポイント（テスト用）
app.get('/api/search', (req, res) => {
  const { query } = req.query;
  
  if (!query) {
    return res.status(400).json({ error: 'Query parameter is required' });
  }
  
  // 危険な文字列パターンを検出（より包括的）
  const dangerousPatterns = [
    'DROP', 'DELETE', 'UPDATE', 'INSERT', 'UNION', 'SELECT',
    '--', ';', '\'', '"', 'EXEC', 'EXECUTE', 'SCRIPT',
    'WAITFOR', 'DELAY', 'SLEEP', 'BENCHMARK', 'EXTRACTVALUE',
    'INFORMATION_SCHEMA', 'pg_sleep', 'CONCAT', 'SUBSTRING'
  ];
  
  const queryUpper = query.toUpperCase();
  const isDangerous = dangerousPatterns.some(pattern => 
    queryUpper.includes(pattern)
  );
  
  if (isDangerous) {
    return res.status(400).json({ error: 'Potentially dangerous query detected' });
  }
  
  const results = users.filter(user => 
    user.name.toLowerCase().includes(query.toLowerCase())
  );
  
  res.json({ query, results });
});

// エラーハンドリング
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404ハンドラ
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

const server = app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = { app, server };