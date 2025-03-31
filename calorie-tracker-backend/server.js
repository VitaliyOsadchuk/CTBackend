require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const User = require("./models/User");
const jwt = require('jsonwebtoken');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
app.use(express.json());
app.use(cors());

// Додавання проксі для обходу CORS
app.use('/proxy', createProxyMiddleware({
    target: 'https://cors-anywhere.herokuapp.com/',
    changeOrigin: true,
    pathRewrite: { '^/proxy': '' },
}));

const port = process.env.PORT || 8080;

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log("MongoDB підключено"))
.catch((err) => console.error("Помилка підключення до MongoDB:", err));

const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
        return res.status(403).json({ message: 'No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

app.post("/api/auth/register", async (req, res) => {
    const { username, password, sex, age, weight, height, activityLevel, plan } = req.body;

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: "Користувач вже існує" });
        }

        const newUser = new User({ username, password, sex, age, weight, height, activityLevel, plan });
        await newUser.save();

        const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(201).json({ message: "Користувач успішно зареєстрований", token });
    } catch (error) {
        console.error("Помилка при реєстрації користувача", error);
        res.status(500).json({ message: "Сталася помилка при реєстрації" });
    }
});

app.post("/api/auth/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user || !(await user.comparePassword(password))) {
            return res.status(400).json({ message: "Невірний логін або пароль" });
        }
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.error("Помилка при вході", error);
        res.status(500).json({ message: "Сталася помилка при вході" });
    }
});

const server = app.listen(port, () => console.log(`Сервер працює на порту ${port}`));

module.exports = app;
