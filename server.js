import express from 'express';
import 'dotenv/config';
import connectDB from './database/db.js';
import userRoute from './routes/userRoute.js'; 
import cors from 'cors';
const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors({
    origin: `${process.env.FRONTEND_URL}`,
    credentials: true
}))

app.use('/user', userRoute)
//http://localhost:8000/user/register

app.get('/', (req, res) => {
    return res.send('Hello World');
})

app.listen(PORT, () => {
    connectDB();
    console.log(`server is listening on port ${PORT}`);
})