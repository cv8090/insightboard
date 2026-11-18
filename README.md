# InsightBoard – data visualization service (DataLens-style)

Node.js + Express + SQLite. Upload CSV/XLSX, build charts, save them to a dashboard, role-based access (admin / editor / viewer).

## Run
    npm install
    JWT_SECRET=change-me npm start      # Windows PowerShell: $env:JWT_SECRET="change-me"; npm start
Open http://localhost:3000. The first registered user becomes admin; later users are editors (admin can change roles in the Admin tab).

## Structure
- server.js – REST API, JWT auth, SQLite (data.db is created automatically)
- public/index.html – frontend (Chart.js + SheetJS from CDN, so internet is needed)

## API
POST /api/register, /api/login · GET /api/state · POST/DELETE /api/datasets · POST/DELETE /api/charts · PUT /api/users/:id/role · DELETE /api/users/:id
