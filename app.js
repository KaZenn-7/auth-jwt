require('dotenv').config();

// imports
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000

// Config JSON response
app.use(express.json());

// Models
const User = require('./models/User'); 

//Middlewares
const checkToken = require('./middlewares/checkToken');


// Open Route - Public Route
app.get('/', (req, res) => {
    return res.status(200).json({msg: "Bem vindo a API"});
})

// Private Route 
app.get('/user/:id', checkToken, async (req, res) => {

    const id = req.params.id;

    //check if user exists
    const user = await User.findById(id, '-password');

    if(!user){
        return res.status(404).json({msg: "Usuário não encontrado!"});
    }

    return res.status(200).json({ user })

});

// Register User
app.post('/auth/register', async (req, res) => {

    const {name, email, password, confirmPassword} = req.body;

    // validations
    if(!name){
        return res.status(422).json({msg: "O nome é obrigatório!"});
    }
    if(!email){
        return res.status(422).json({msg: "O email é obrigatório!"});
    }
    if(!password){
        return res.status(422).json({msg: "O password é obrigatório!"});
    }
    if(password !== confirmPassword) {
        return res.status(422).json({msg: "As senhas não são iguais!"});
    }

    //check if user exists
    const userExists = await User.findOne({email: email});

    if(userExists){
        return res.status(422).json({msg: "Este email ja está cadastrado!"});
    }

    //gen password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    //create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })


    try{

        await user.save();
        return  res.status(201).json({msg: "User saved!"});

    } catch (err) { 

        console.error(err);
        return res.status(500).json({msg: "Ocorreu um erro no servidor, tente novamente mais tarde!"});

    }


});

// Login user
app.post('/auth/login', async (req, res) => {

    const { email, password } = req.body;
    
    //validations
    if(!email){
        return res.status(422).json({msg: "O email é obrigatório!"});
    }
    if(!password){
        return res.status(422).json({msg: "O password é obrigatório!"});
    }
    
    //check if user exists
    const user = await User.findOne({email: email});

    if(!user){
        return res.status(404).json({msg: "Usuário não encontrado!"});
    }

    //check if password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if(!checkPassword){
        return res.status(422).json({msg: "Senha inválida!"});
    }

    try {

        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id
            },
            secret
        )

        return res.status(200).json({msg: "Autenticação realizada com sucesso!", token});

    } catch(err) {

        console.error(err);
        return res.status(500).json({msg: "Ocorreu um erro no servidor, tente novamente mais tarde!"});

    }

});

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.jwe2t.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`).then(() => {
    console.log("Connected to MongoDB");

    app.listen(port, ()=>{
        console.log(`listening on ${port}`)
        console.log(`http://localhost:${port}`)
    }); 

}).catch((err) => console.error(err));    
