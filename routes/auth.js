const express = require('express');
const { register, login, verifyEmail } = require('../controllers/authControllers');
const auth = require('../middlewarre/auth');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/verify/:token', verifyEmail);

module.exports = router;
