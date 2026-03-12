const express = require('express');
const { exec } = require('child_process');
const mysql = require('mysql');

const app = express();
const connection = mysql.createConnection({ host: 'localhost', user: 'root', password: 'hardcoded_password123' });

app.get('/ping', (req, res) => {
    // OS Command Injection
    exec('ping -c 4 ' + req.query.ip, (err, stdout, stderr) => {
        res.send(stdout);
    });
});

app.get('/user', (req, res) => {
    // SQL Injection
    let userId = req.query.id;
    connection.query('SELECT * FROM users WHERE id = ' + userId, (err, results) => {
        res.json(results);
    });
});

app.listen(3000);
