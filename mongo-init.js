// Chuyển sang sử dụng database easm_db
db = db.getSiblingDB('easm_db');

// 1. Tạo User cho FastAPI kết nối ngầm (Không thay đổi)
db.createUser({
  user: "easm_app_user",
  pwd: "SuperSecretPassword123!",
  roles: [ { role: "readWrite", db: "easm_db" } ]
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
        password_hash: "$2b$12$/kJZyc05qjt/xqnu/p6JTu1pFF3GsBNyVi6sHMpXKndWIWZW8NODO", 
        role: "admin",
        created_at: new Date()
    },
    {
        _id: "admin_002",
        username: "phuocthien7733",
        password_hash: "$2b$12$MCNt/JElWSjVs7KVXXlKF.WcSLsMDAZf0r7z6Qyrr6BkVnitSsWti", 
        role: "admin",
        created_at: new Date()
    }
]);

print("done");