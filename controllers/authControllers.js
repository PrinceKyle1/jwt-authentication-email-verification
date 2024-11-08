const User = require('../models/User');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');

// Register Controller
exports.register = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = new User({ email, password });
        await user.save();

        // Generate verification token and send email
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        const verificationLink = `http://localhost:${process.env.PORT}/api/auth/verify/${token}`;

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASSWORD },
        });
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Email Verification',
            text: `Click on the link to verify your email: ${verificationLink}`,
        });

        res.status(201).json({ message: 'User registered. Check your email to verify your account.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Login Controller
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid email or password' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid email or password' });

        if (!user.isVerified) return res.status(401).json({ message: 'Please verify your email first' });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Email Verification Controller
exports.verifyEmail = async (req, res) => {
    try {
        const { token } = req.params;
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await User.findById(decoded.id);
        if (!user) return res.status(400).json({ message: 'Invalid token' });

        user.isVerified = true;
        await user.save();
        res.json({ message: 'Email verified successfully' });
    } catch (err) {
        res.status(400).json({ message: 'Invalid or expired token' });
    }
};

// Request Password Reset Controller
exports.requestPasswordReset = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: 'User not found' });

        const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const resetLink = `http://localhost:${process.env.PORT}/api/auth/reset/${resetToken}`;

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASSWORD },
        });
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Password Reset Request',
            text: `Click on the link to reset your password: ${resetLink}`,
        });

        res.json({ message: 'Password reset email sent. Please check your inbox.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Password Reset Controller
exports.resetPassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { newPassword } = req.body;

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ message: 'User not found' });

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
        res.json({ message: 'Password reset successfully' });
    } catch (err) {
        res.status(400).json({ message: 'Invalid or expired token' });
    }
};
