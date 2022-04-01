const mysql = require('mysql2');
// สร้างการเชื่อมต่อกับฐานช้อมูล
const dbConnection = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "nodejs_login"
}).promise()

module.exports = dbConnection;