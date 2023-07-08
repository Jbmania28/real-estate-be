const express = require('express')
const mysql = require('mysql')
const cors = require('cors');
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const bodyParser = require('body-parser')
const bcrypt = require('bcrypt')
const secretKey = "jwtSecretKey"
const app = express();
const salt = 10;
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "signup"
})

app.post('/signup', (req, res) => {
    const sql = "INSERT INTO login(`fname`,`lname`,`email`,`password`) values(?)";
    const password = req.body.password;
    bcrypt.hash(password.toString(), salt, (err, hash) => {
        if (err) {
            console.log(err);
        }
        const values = [
            req.body.fname,
            req.body.lname,
            req.body.email,
            hash
        ]
        db.query(sql, [values], (err, data) => {
            if (err) {
                return res.json("Error");
            }
            return res.json(data);
        })

    })
})

app.post('/contactus', (req, res) => {
    const sql = "INSERT INTO contactus(`name`,`email`,`contact`,`message`) values(?)";
    const values = [
        req.body.name,
        req.body.email,
        req.body.contact,
        req.body.message,
    ]
    db.query(sql, [values], (err, data) => {
        if (err) {
            return res.json("Error");
        }
        return res.json(data);
    })
})

app.post('/login', (req, res) => {
    const sql = "select * from login WHERE email = ?";
    db.query(sql, [req.body.email], (err, data) => {
        if (err) {
            return res.json("Error");
        }
        if (data.length > 0) {
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, resp) => {
                if (err) {
                    console.log("password mismatched error",err);
                    return res.json("Password Not Matched");
                }
                if (resp) {
                    console.log("generating token");
                    const id = data[0].id;
                    const token = jwt.sign({ id }, secretKey, { expiresIn: '1h' });
                    return res.json({ login: true, token, data });
                } else {
                    return res.json({ login: false });
                }
            })

        } else {
            return res.json("user not found");
        }
    })
})

app.post('/profile', verifyToken, (req, res) => {
    jwt.verify(req.token, secretKey, (err, authData) => {
        if (err) {
            return res.json({ result: false })
        } else {
            return res.json({ result: true, authData })
        }
    })
})

function verifyToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined') {
        const bearer = bearerHeader.split(" ");
        const token = bearer[1];
        req.token = token;
        next();
    } else {
        res.send({
            result: "token is not valid"
        })
    }
}

app.get('/getUserById', (req, res) => {
    const id = parseInt(req.query.id);
    const sql = "SELECT * FROM login WHERE `id` = ? ";
    db.query(sql, [id], (err, data) => {
        if (err) {
            return res.json({ result: false });
        } else {
            return res.json({ result: true, data });
        }
    });
});

// app.get('/',(req,res)=>{
//     let token = JSON.parse(localStorage.getItem('token'))
//     console.log(token);
//       if(!token){
//         return res.json({valid:false})
//       }else{
//         return res.json({valid:true})
//       }
// }
// )

app.listen(5000, () => {
    console.log("listening on port 5000");
})

