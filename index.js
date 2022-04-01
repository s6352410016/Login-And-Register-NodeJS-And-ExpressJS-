const express = require('express')
const path = require('path')
const cookieSession = require('cookie-session')
const bcrypt = require('bcrypt')
const dbConnection = require('./database')
const {body , validationResult} = require('express-validator')

const app = express()
app.use(express.urlencoded({extended:false}))

app.set('views',path.join(__dirname,'views'))
app.set('view engine','ejs')

app.use(cookieSession({
    name: 'session',
    keys: ['key1','key2'],
    maxAge: 3600 * 1000 // เท่ากับ 1 ชม.
}))

// สร้าง Middleware ขึ้นมา
const ifNotLoggedin = (req,res,next) =>{
    // ถ้าไม่ได้มีการ login เข้ามา
    if(!req.session.ifLoggedIn){
        return res.render('login-register')
    }
    next()
}

// สร้าง Middleware ขึ้นมา
const ifLoggedin = (req,res,next) => {
    if(req.session.ifLoggedIn){
        return res.redirect('/home')
    }
    next()
}

// root page
app.get('/' , ifNotLoggedin , (req,res) =>{
    dbConnection.execute("SELECT name FROM users WHERE id = ?" , [req.session.userID])
    // เช็คข้อมูลที่อยู่ในตารางถ้าเกิดมีข้อมูลอยู่ ให้แสดงหน้า home
    .then(([rows]) => {
        res.render('home', {
            name: rows[0].name
        })
    })
})

// Register Page
app.post('/register' , [
    // validate email in form 
    body('user_email' , 'Invalid Email Address!').isEmail().custom((value) => {
        return dbConnection.execute('SELECT email FROM users WHERE email = ?' , [value])
        .then(([rows]) => {
            if(rows.length > 0){
                return Promise.reject('This Email already exist!')
            }
            return true
        })
    }),
    // validate username in form 
    body('user_name' , 'Username is empty').trim().not().isEmpty(),
    // validate password in form 
    body('user_pass' , 'The password must be minimum length 6 Characters').trim().isLength({min:6}),

],// end of validate
    // เพิ่มข้อมูลไปเก็บในฐานช้อมูล
    (req,res,) => {
        // นำข้อมูลที่ส่ง request มา validation และก็เก็บลงตัวแปร
        const validation_result = validationResult(req)
        const {user_name , user_email , user_pass} = req.body

        // เช็คข้อมูลที่เก็บในตัวแปรถ้าไม่มี error ใดๆเลยให้ทำอะไร
        if(validation_result.isEmpty()){
            // เขารหัส password
            bcrypt.hash(user_pass, 12).then((hash_pass) => {
                dbConnection.execute('INSERT INTO users (name , email , password) VALUES(? , ? , ?)', [user_name , user_email , hash_pass])
                .then(() => {
                    res.send(`Your account has been created successfully, Now you can <a href='/'>Login</a>`)
                }).catch(err => {
                    if(err){
                        throw err
                    }
                })
            }).catch(err => {
                if(err){
                    throw err
                }
            })
        }else{
            let allErrors = validation_result.errors.map((error) => {
                return error.msg
            })
            res.render('login-register',{
                register_error: allErrors,
                old_data: req.body
            })
        }
    })

// Login Page
app.post('/', [
    body('user_email').custom((value) =>{
        return dbConnection.execute('SELECT email FROM users WHERE email = ?', [value])
        .then(([rows]) => {
            if(rows.length == 1){
                return true
            }
            return Promise.reject('Invalid Email Address!')
        }) 
    }),
    body('user_pass' , 'Password is empty').trim().not().isEmpty(),
], (req,res) => {
    const validation_result = validationResult(req)
    const {user_email , user_pass} = req.body
    // เช็คข้อมูลที่เก็บในตัวแปรถ้าไม่มี error ใดๆเลยให้ทำอะไร
    if(validation_result.isEmpty()){
        dbConnection.execute('SELECT * FROM users WHERE email = ?', [user_email])
        .then(([rows]) => {
            // เปรียบเทียบรหัสที่กรอกเข้ามากับรหัสที่ทำการ เข้ารหัสว่าตรงกันไหม 
            bcrypt.compare(user_pass , rows[0].password).then(compare_result => {
                if(compare_result === true){
                    // ทำการเก็บ session
                    req.session.ifLoggedIn = true;
                    req.session.userID = rows[0].id;
                    res.redirect('/');
                }else{
                    res.render('login-register',{
                        login_errors: ["Invalid Password"]
                    })
                }
            }).catch(err => {
                if(err){
                    throw err
                }
            })
        }).catch(err => {
            if(err){
                throw err
            }
        })
    }else{
        let allErrors = validation_result.errors.map(err => {
            return err.msg
        })
        res.render('login-register',{
            login_errors: allErrors
        })
    }
})

// logout
app.get('/logout',(req,res) => {
    req.session = null
    res.redirect('/')
})

// ถ้าค้นหา path ผิด
app.use('/',(req,res) => {
    res.status(404).send('<h1>404 Page not found!</h1>')
})

app.listen(3000 , () => console.log('Server is running...'))