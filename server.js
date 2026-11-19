const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');

const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.JWT_SECRET) console.warn('JWT_SECRET не задан: после перезапуска пользователям нужно будет войти снова.');

const db = new Database(process.env.DB_FILE || path.join(__dirname, 'data.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT UNIQUE COLLATE NOCASE, pass TEXT, role TEXT);
  CREATE TABLE IF NOT EXISTS datasets(id TEXT PRIMARY KEY, name TEXT, cols TEXT, types TEXT, rows TEXT, owner TEXT);
  CREATE TABLE IF NOT EXISTS charts(id TEXT PRIMARY KEY, title TEXT, type TEXT, ds TEXT, x TEXT, y TEXT, agg TEXT, owner TEXT);
`);

// Добавляем новые поля к существующим базам без удаления сохранённых данных.
const chartColumns = new Set(db.prepare('PRAGMA table_info(charts)').all().map(column => column.name));
for (const [name, type] of [['ds2', 'TEXT'], ['x2', 'TEXT'], ['y2', 'TEXT'], ['min_value', 'REAL'], ['max_value', 'REAL']]) {
  if (!chartColumns.has(name)) db.exec(`ALTER TABLE charts ADD COLUMN ${name} ${type}`);
}

const app = express();
app.use(express.json({ limit: '30mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const uid = () => crypto.randomBytes(5).toString('hex');
const sign = user => jwt.sign({ id: user.id }, SECRET, { expiresIn: '7d' });
const publicUser = user => ({ id: user.id, name: user.name, role: user.role });
const ROLES = ['admin', 'editor', 'viewer'];
const TYPES = ['bar', 'line', 'pie', 'doughnut', 'scatter'];
const AGGS = ['sum', 'avg', 'max', 'count'];
const isString = (value, max) => typeof value === 'string' && value.length > 0 && value.length <= max;

function authenticate(req, res, next) {
  try {
    const userId = jwt.verify((req.headers.authorization || '').slice(7), SECRET).id;
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(userId);
    if (!user) throw new Error('Пользователь не найден');
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Необходимо войти в систему.' });
  }
}

const allowRoles = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Недостаточно прав.' });

const owns = table => (req, res, next) => {
  const record = db.prepare(`SELECT owner FROM ${table} WHERE id=?`).get(req.params.id);
  if (!record) return res.status(404).json({ error: 'Запись не найдена.' });
  if (req.user.role === 'admin' || (req.user.role === 'editor' && record.owner === req.user.id)) return next();
  res.status(403).json({ error: 'Недостаточно прав.' });
};

function numericLimit(value) {
  if (value === undefined || value === null || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : NaN;
}

function getDataset(id) {
  const dataset = db.prepare('SELECT id, cols FROM datasets WHERE id=?').get(id);
  return dataset ? { ...dataset, cols: JSON.parse(dataset.cols) } : null;
}

app.post('/api/register', (req, res) => {
  const { name, pass } = req.body || {};
  if (!isString(name, 40) || name.trim().length < 2 || !isString(pass, 200) || pass.length < 4) {
    return res.status(400).json({ error: 'Введите имя пользователя (не менее 2 символов) и пароль (не менее 4 символов).' });
  }
  if (db.prepare('SELECT 1 FROM users WHERE name=?').get(name.trim())) {
    return res.status(409).json({ error: 'Это имя пользователя уже занято.' });
  }
  const firstUser = !db.prepare('SELECT 1 FROM users').get();
  const user = { id: uid(), name: name.trim(), pass: bcrypt.hashSync(pass, 10), role: firstUser ? 'admin' : 'editor' };
  db.prepare('INSERT INTO users VALUES(@id,@name,@pass,@role)').run(user);
  res.json({ token: sign(user), user: publicUser(user) });
});

app.post('/api/login', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE name=?').get(String((req.body || {}).name || '').trim());
  if (!user || !bcrypt.compareSync(String((req.body || {}).pass || ''), user.pass)) {
    return res.status(401).json({ error: 'Неверное имя пользователя или пароль.' });
  }
  res.json({ token: sign(user), user: publicUser(user) });
});

app.get('/api/state', authenticate, (req, res) => {
  const parse = JSON.parse;
  res.json({
    me: publicUser(req.user),
    users: req.user.role === 'admin' ? db.prepare('SELECT id,name,role FROM users').all() : [],
    datasets: db.prepare('SELECT * FROM datasets').all().map(dataset => ({
      ...dataset,
      cols: parse(dataset.cols),
      types: parse(dataset.types),
      rows: parse(dataset.rows)
    })),
    charts: db.prepare('SELECT * FROM charts').all()
  });
});

app.post('/api/datasets', authenticate, allowRoles('admin', 'editor'), (req, res) => {
  const dataset = req.body || {};
  if (!isString(dataset.name, 200) || !Array.isArray(dataset.cols) || !Array.isArray(dataset.rows) ||
      !dataset.rows.length || dataset.rows.length > 5000) {
    return res.status(400).json({ error: 'Файл должен содержать от 1 до 5000 строк и строку заголовков.' });
  }
  db.prepare('INSERT INTO datasets VALUES(?,?,?,?,?,?)').run(
    uid(), dataset.name, JSON.stringify(dataset.cols), JSON.stringify(dataset.types || {}),
    JSON.stringify(dataset.rows), req.user.id
  );
  res.json({ ok: 1 });
});

app.delete('/api/datasets/:id', authenticate, owns('datasets'), (req, res) => {
  db.prepare('DELETE FROM charts WHERE ds=? OR ds2=?').run(req.params.id, req.params.id);
  db.prepare('DELETE FROM datasets WHERE id=?').run(req.params.id);
  res.json({ ok: 1 });
});

app.post('/api/charts', authenticate, allowRoles('admin', 'editor'), (req, res) => {
  const chart = req.body || {};
  const dataset = getDataset(chart.ds);
  const comparison = chart.ds2 ? getDataset(chart.ds2) : null;
  const minValue = numericLimit(chart.min_value);
  const maxValue = numericLimit(chart.max_value);
  const hasInvalidLimit = Number.isNaN(minValue) || Number.isNaN(maxValue);
  const hasInvalidComparison = chart.ds2 && (
    !comparison || chart.ds2 === chart.ds || !['bar', 'line', 'scatter'].includes(chart.type) ||
    !comparison.cols.includes(chart.x2) || !comparison.cols.includes(chart.y2)
  );

  if (!isString(chart.title, 200) || !TYPES.includes(chart.type) || !AGGS.includes(chart.agg) ||
      !dataset || !dataset.cols.includes(chart.x) || !dataset.cols.includes(chart.y) ||
      hasInvalidComparison || hasInvalidLimit ||
      (minValue !== null && maxValue !== null && minValue >= maxValue)) {
    return res.status(400).json({ error: 'Проверьте тип графика, наборы данных, столбцы и границы оповещений.' });
  }

  db.prepare(`INSERT INTO charts
    (id,title,type,ds,x,y,agg,owner,ds2,x2,y2,min_value,max_value)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    uid(), chart.title, chart.type, chart.ds, chart.x, chart.y, chart.agg, req.user.id,
    chart.ds2 || null, chart.ds2 ? chart.x2 : null, chart.ds2 ? chart.y2 : null, minValue, maxValue
  );
  res.json({ ok: 1 });
});

app.delete('/api/charts/:id', authenticate, owns('charts'), (req, res) => {
  db.prepare('DELETE FROM charts WHERE id=?').run(req.params.id);
  res.json({ ok: 1 });
});

app.post('/api/users', authenticate, allowRoles('admin'), (req, res) => {
  const { name, pass, role } = req.body || {};
  if (!isString(name, 40) || name.trim().length < 2 || !isString(pass, 200) || pass.length < 4 || !ROLES.includes(role)) {
    return res.status(400).json({ error: 'Укажите имя (не менее 2 символов), пароль (не менее 4 символов) и роль.' });
  }
  if (db.prepare('SELECT 1 FROM users WHERE name=?').get(name.trim())) {
    return res.status(409).json({ error: 'Это имя пользователя уже занято.' });
  }
  const user = { id: uid(), name: name.trim(), pass: bcrypt.hashSync(pass, 10), role };
  db.prepare('INSERT INTO users VALUES(@id,@name,@pass,@role)').run(user);
  res.status(201).json({ user: publicUser(user) });
});

app.put('/api/users/:id/role', authenticate, allowRoles('admin'), (req, res) => {
  const role = (req.body || {}).role;
  if (req.params.id === req.user.id || !ROLES.includes(role)) {
    return res.status(400).json({ error: 'Нельзя изменить собственную роль или указана неверная роль.' });
  }
  const result = db.prepare('UPDATE users SET role=? WHERE id=?').run(role, req.params.id);
  if (!result.changes) return res.status(404).json({ error: 'Пользователь не найден.' });
  res.json({ ok: 1 });
});

app.delete('/api/users/:id', authenticate, allowRoles('admin'), (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Нельзя удалить собственную учётную запись.' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ ok: 1 });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`InsightBoard запущен: http://localhost:${port}`));
