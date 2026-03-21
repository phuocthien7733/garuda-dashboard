const dbName = process.env.MONGO_DB_NAME || 'easm_db';
const appUsername = process.env.MONGO_APP_USERNAME || 'easm_app_user';
const appPassword = process.env.MONGO_APP_PASSWORD || 'SuperSecretPassword123!';

// Chuyển sang sử dụng database easm_db
db = db.getSiblingDB(dbName);

// 1. Tạo User cho FastAPI kết nối ngầm (Không thay đổi)
db.createUser({
  user: appUsername,
  pwd: appPassword,
  roles: [ { role: "readWrite", db: dbName } ]
});

// 2. Dựng sẵn các Collections
db.createCollection('assets');
db.createCollection('vulnerabilities');
db.createCollection('users');

// 3. Bơm data 2 tài khoản Tối Cao (Seed Users)
db.users.insertMany([
    {
        _id: "admin_001",
        username: "administrator",
        email: "administrator@testandwatch.local",
        password_hash: "$2b$12$/kJZyc05qjt/xqnu/p6JTu1pFF3GsBNyVi6sHMpXKndWIWZW8NODO", 
        role: "admin",
        mfa_enabled: false,
        created_at: new Date()
    },
    {
        _id: "admin_002",
        username: "phuocthien7733",
        email: "phuocthien7733@testandwatch.local",
        password_hash: "$2b$12$MCNt/JElWSjVs7KVXXlKF.WcSLsMDAZf0r7z6Qyrr6BkVnitSsWti", 
        role: "admin",
        mfa_enabled: false,
        created_at: new Date()
    }
]);

print("done");
