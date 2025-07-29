import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { User } from '../models/usermodel.js';
import { generateAccessToken, generateRefreshToken } from '../utils/jwtutils.js';

const refreshTokens = new Set(); // In-memory store (use DB/Redis in production)

export const signup = async (req, res) => {
  const { username, email, password } = req.body;
  const existing = await User.findOne({ $or: [{ username }, { email }] });
  if (existing) return res.status(400).json({ message: 'User already exists' });

  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, email, password: hashed });
  await user.save();
  return res.status(201).json({ message: 'Signup successful' });
};

export const login = async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ message: 'User not found' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: 'Invalid credentials' });

  const payload = { id: user._id, username: user.username };
  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload);

  refreshTokens.add(refreshToken); // Save valid token

  return res.json({ accessToken, refreshToken });
};

export const refreshToken = (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: 'Token required' });
  if (!refreshTokens.has(token)) return res.status(403).json({ message: 'Invalid refresh token' });

  jwt.verify(token, process.env.REFRESH_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    const accessToken = generateAccessToken({ id: user.id, username: user.username });
    return res.json({ accessToken });
  });
};

export const logout = (req, res) => {
  const { token } = req.body;
  refreshTokens.delete(token);
  res.json({ message: 'Logged out' });
};
