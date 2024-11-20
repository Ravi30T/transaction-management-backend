const express = require('express')
const {MongoClient} = require('mongodb')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const {v4:uuidv4} = require('uuid')
const cors = require('cors')
require('dotenv').config()
const app = express()
app.use(express.json())
app.use(cors())

let client

const initializeDBAndServer = async () => {
    const dbUser = process.env.DB_USER
    const dbPassword = process.env.DB_PASSWORD
    const dbCluster = process.env.DB_CLUSTER
    const dbName = process.env.DB_NAME
    const uri = `mongodb+srv://${dbUser}:${dbPassword}@${dbCluster}/${dbName}?retryWrites=true&w=majority`;

    client = new MongoClient(uri)

    try{
        await client.connect()
        console.log("Connected to MongoDB...")
        const PORT = process.env.PORT || 3000

        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`)
        })
    }
    catch(e){
        console.log(`Error Connecting to MongoDB: ${e.message}`)
        process.exit(1)
    }
}

initializeDBAndServer()


// Middleware Function

const authenticateToken = (request, response, next) => {
    let jwtToken

    const authHeader = request.headers["authorization"]

    if(authHeader !== undefined){
        jwtToken = authHeader.split(" ")[1]
    }
    if(jwtToken === undefined){
        response.status(401).send({message: "Invalid JWT Token"})
    }
    else{
        jwt.verify(jwtToken, "MY_SECRET_TOKEN", async(error, payload) => {
            if(error){
                response.status(401).send({message: error})
            }
            else{
                request.userId = payload.userId
                next()
            }
        })
        
    }
}

// API-1 Create New User

app.post('/register', async(request, response) => {
    const {username, email, password} = request.body
    const userCollection = client.db(process.env.DB_NAME).collection('users')

    const checkUserInDB = await userCollection.find({email}).toArray()
    const checkUsernameInDB = await userCollection.find({userName: username}).toArray()

    try{
        if(checkUserInDB.length === 0){
            if(checkUsernameInDB.length === 0){
                const hashedPassword = await bcrypt.hash(password, 10)
    
                if(username !== undefined && email !== undefined && password !== undefined){
                    const userDetails = {
                        userId: uuidv4(),
                        userName: username,
                        email: email,
                        password: hashedPassword,
                        accountBalance: 0
                    }
    
                    await userCollection.insertOne(userDetails)
                    response.status(201).send({message: "User Registered Successfully"})
                }
                else{
                    response.status(401).send({message: "Please Enter Valid User Details"})
                }
            }
            else{
                response.status(401).send({message: "Username Already Used"})
            }
        }
        else{
            response.status(401).send({message: "User Already Exists"})
        }
    }
    catch(e){
        response.status(500).send({message: "Internal Server Error"})
    }
    
})

// API - 2 User Login

app.post('/login', async(request, response) => {
    const {username, password} = request.body
    const userCollection = client.db(process.env.DB_NAME).collection('users')

    const checkUserInDB = await userCollection.find({userName: username}).toArray()

    try{
        if(checkUserInDB.length === 1){
            const verifyPassword = await bcrypt.compare(password, checkUserInDB[0].password)
    
            if(verifyPassword){
                const token = jwt.sign({userId: checkUserInDB[0].userId}, 'MY_SECRET_TOKEN')
                response.status(201).send({userId: checkUserInDB[0].userId, jwtToken: token})
            }
            else{
                response.status(401).send({message: "Incorrect Password"})
            }
        }
        else{
            response.status(401).send({message: "User Doesn't Exist"})
        }
    }
    catch(e){
        response.status(500).send({message: "Internal Server Error"})
    }
})


// API - 3 Create a new transaction


app.post('/api/transactions/', authenticateToken, async(request, response) => {
    const {userId} = request
    const {user, amount, transactionType } = request.body
    const userCollection = client.db(process.env.DB_NAME).collection('users')
    const checkUserInDB = await userCollection.find({userId: user}).toArray()

    const transactionsCollection = client.db(process.env.DB_NAME).collection('transactions')

    try{
        if(checkUserInDB.length === 1 && userId === user){
            if(amount !== undefined && transactionType !== undefined){
                const timestamp = new Date().toISOString();
    
                if(transactionType === 'DEPOSIT'){
                    const updatedBalance = parseFloat(checkUserInDB[0].accountBalance) + parseFloat(amount)
                    const newTransaction = {
                        transaction_id: uuidv4(),
                        amount: parseFloat(amount),
                        transaction_type: transactionType,
                        status: "PENDING",
                        user: user,
                        timestamp: timestamp,
                    }
    
                    await userCollection.updateOne({userId: user}, {$set: {accountBalance: parseFloat(updatedBalance)}})
                    await transactionsCollection.insertOne(newTransaction)
                    response.status(201).send({message: "Transaction Completed Successfully"})
                }
                else{
                    const availableBalance = parseFloat(checkUserInDB[0].accountBalance)
    
                    if(amount < availableBalance){
                        const updatedBalance = availableBalance - parseFloat(amount)
                        const newTransaction = {
                            transaction_id: uuidv4(),
                            amount: parseFloat(amount),
                            transaction_type: transactionType,
                            status: "PENDING",
                            user: user,
                            timestamp: timestamp,
                        }
    
                        await userCollection.updateOne({userId: user}, {$set: {accountBalance: parseFloat(updatedBalance)}})
                        await transactionsCollection.insertOne(newTransaction)
                        response.status(201).send({message: "Transaction Completed Successfully"})
                    }
                    else{
                        response.status(401).send({message: "Insufficient Amount"})
                    }
                }
            }
            else{
                response.status(401).send({message: "Please Provide Valid Transaction Details "})
            }
        }
        else{
            response.status(401).send({message: "Invalid User Request"})
        }
    }
    catch(e){
        response.status(500).send({message: "Internal Server Error"})
    }
})


// API - 4 Get All Transaction Details of logged-in user

app.get('/api/transactions/', authenticateToken, async(request, response) => {
    const {userId} = request
    const userCollection = client.db(process.env.DB_NAME).collection('users')

    const checkUserInDB = await userCollection.find({userId}).toArray()
    if(checkUserInDB.length === 1){
        const transactionsCollection = client.db(process.env.DB_NAME).collection('transactions')

        const getUserTransactions = await transactionsCollection.find({user: userId},
            {projection: {
                transaction_id: 1,
                amount: 1,
                transaction_type: 1,
                status: 1,
                timestamp: 1,
                _id: 0
            }}).toArray()

        if(getUserTransactions.length > 0){
            response.status(201).send(getUserTransactions)
        }
        else{
            response.status(401).send({message: "No Transactions"})
        }
    }
    else{
        response.status(401).send({message: "Invalid Request"})
    }
})

// API - 5 Update Transaction Status

app.put('/api/transactions/:transaction_id/', authenticateToken, async(request, response) => {
    const {transaction_id} = request.params
    const {userId} = request
    const {status} = request.body

    try{
        const userCollection = client.db(process.env.DB_NAME).collection('users')
        const checkUserInDB = await userCollection.find({userId}).toArray()

        if(checkUserInDB.length === 1){
            const transactionsCollection = client.db(process.env.DB_NAME).collection('transactions') 

            const checkTransaction = await transactionsCollection.find({transaction_id}).toArray() // to check transaction is available or not

            if(checkTransaction.length === 1 && checkTransaction[0].status !== 'COMPLETED'){
                const timestamp = new Date().toISOString();
                
                await transactionsCollection.updateOne({transaction_id, user: userId}, 
                    {$set: {status, timestamp}}
                )

                response.status(201).send({message: "Transaction Status Updated Successfully"})
            }
            else{
                response.status(401).send({message: "Invalid Transaction Details"})
            }
        }
        else{
            response.status(401).send({message: "Invalid Request"})
        }
    }
    catch(e){
        const transactionsCollection = client.db(process.env.DB_NAME).collection('transactions')

        const timestamp = new Date().toISOString();
                
        await transactionsCollection.updateOne({transaction_id, user: userId}, 
            {$set: {status: "FAILED", timestamp}}
        )

        response.status(500).send({message: "Internal Server Error"});
    }
    
})


// API - 6 Get Transaction Details

app.get('/api/transactions/:transaction_id/', authenticateToken, async(request, response) => {
    const {userId} = request
    const {transaction_id} = request.params

    try{
        const userCollection = client.db(process.env.DB_NAME).collection('users')
        const checkUserInDB = await userCollection.find({userId}).toArray()
        const transactionsCollection = client.db(process.env.DB_NAME).collection('transactions')
        const getTransaction = await transactionsCollection.find({transaction_id}).toArray()

        if(checkUserInDB.length === 1 && userId === getTransaction[0].user){
            const checkTransaction = await transactionsCollection.find({transaction_id},
                {projection: {
                    transaction_id: 1,
                    amount: 1,
                    transaction_type: 1,
                    status: 1,
                    timestamp: 1,
                    _id: 0
                }}
            ).toArray()

            if(checkTransaction.length === 1){
                response.status(201).send(checkTransaction)
            }
            else{
                response.status(401).send({message: "Invalid Transaction Details"})
            }
        }
        else{
            response.status(401).send({message: "Invalid User Request"})
        }
    }
    catch(e){
        response.status(500).send({message: "Internal Server Error"})
    }  
})