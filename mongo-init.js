const dbName = process.env.MONGO_DB_NAME || "easm_db";
const appUsername = process.env.MONGO_APP_USERNAME || "easm_app_user";
const appPassword = process.env.MONGO_APP_PASSWORD || "SuperSecretPassword123!";
const shouldSeedUsers = (process.env.MONGO_SEED_DEFAULT_USERS || "false").toLowerCase() === "true";

db = db.getSiblingDB(dbName);

db.createUser({
  user: appUsername,
  pwd: appPassword,
  roles: [{ role: "readWrite", db: dbName }],
});

const requiredCollections = ["assets", "vulnerabilities", "vulnerabilities_archive", "users", "dashboard_snapshots"];
const existingCollections = db.getCollectionNames();
requiredCollections.forEach((collectionName) => {
  if (!existingCollections.includes(collectionName)) {
    db.createCollection(collectionName);
  }
});

if (shouldSeedUsers) {
  const seedUsers = [
    {
      username: process.env.MONGO_SEED_ADMIN_USERNAME || "administrator",
      email: process.env.MONGO_SEED_ADMIN_EMAIL || "administrator@example.com",
      password_hash:
        process.env.MONGO_SEED_ADMIN_PASSWORD_HASH ||
        "$2b$12$/kJZyc05qjt/xqnu/p6JTu1pFF3GsBNyVi6sHMpXKndWIWZW8NODO",
      role: "admin",
      mfa_enabled: false,
      created_at: new Date(),
    },
  ];

  seedUsers.forEach((user) => {
    db.users.updateOne(
      { username: user.username },
      { $setOnInsert: user },
      { upsert: true },
    );
  });
  print("Mongo init: default users seeded.");
} else {
  print("Mongo init: default user seeding is disabled.");
}

print("Mongo init completed.");
