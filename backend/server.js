const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: ['http://127.0.0.1:5500', 'http://localhost:5500'],
    credentials: true
}));
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

// ==================== SCHEMAS ====================

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    wallet: { type: Number, default: 1000 }, // Starting bonus
    createdAt: { type: Date, default: Date.now }
});

// Item Schema
const itemSchema = new mongoose.Schema({
    name: { type: String, required: true },
    icon: { type: String, required: true },
    description: { type: String, required: true },
    price: { type: Number, required: true },
    createdBy: { type: String, default: 'admin' },
    createdAt: { type: Date, default: Date.now }
});

// Transaction Schema
const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: { type: String, enum: ['deposit', 'withdraw', 'purchase'], required: true },
    amount: { type: Number, required: true },
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'Item' },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
    description: String,
    createdAt: { type: Date, default: Date.now }
});

// Purchase Schema
const purchaseSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'Item' },
    itemName: String,
    price: Number,
    purchaseDate: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Item = mongoose.model('Item', itemSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Purchase = mongoose.model('Purchase', purchaseSchema);

// ==================== MIDDLEWARE ====================

// Auth Middleware
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) throw new Error();

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user) throw new Error();

        req.user = user;
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};

// Admin Middleware
const adminAuth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) throw new Error();

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user || user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        req.user = user;
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Authentication failed' });
    }
};

// ==================== INITIALIZE ADMIN ====================
async function initializeAdmin() {
    try {
        const adminExists = await User.findOne({ role: 'admin' });
        
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
            
            const admin = new User({
                name: 'Global Admin',
                username: process.env.ADMIN_USERNAME,
                email: 'admin@ahadxtoolkit.com',
                password: hashedPassword,
                role: 'admin',
                wallet: 999999 // Infinite wallet for admin
            });
            
            await admin.save();
            console.log('✅ Admin account created successfully');
            console.log('📧 Email: admin@ahadxtoolkit.com');
            console.log('🔑 Username:', process.env.ADMIN_USERNAME);
            console.log('🔐 Password:', process.env.ADMIN_PASSWORD);
        } else {
            console.log('✅ Admin account already exists');
        }
    } catch (error) {
        console.error('❌ Admin creation error:', error);
    }
}

// ==================== AUTH ROUTES ====================

// Register User
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, username, email, password } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ 
            $or: [{ email }, { username }] 
        });
        
        if (existingUser) {
            return res.status(400).json({ 
                error: 'User with this email or username already exists' 
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user (always as regular user)
        const user = new User({
            name,
            username,
            email,
            password: hashedPassword,
            role: 'user',
            wallet: 1000 // Starting bonus
        });

        await user.save();

        // Generate token
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            token,
            user: {
                id: user._id,
                name: user.name,
                username: user.username,
                email: user.email,
                role: user.role,
                wallet: user.wallet
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate token
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            token,
            user: {
                id: user._id,
                name: user.name,
                username: user.username,
                email: user.email,
                role: user.role,
                wallet: user.wallet
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ==================== WALLET ROUTES ====================

// Get Balance
app.get('/api/wallet/balance', auth, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        res.json({ balance: user.wallet });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch balance' });
    }
});

// Deposit
app.post('/api/wallet/deposit', auth, async (req, res) => {
    try {
        const { amount } = req.body;
        
        if (amount <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }

        const user = await User.findById(req.userId);
        user.wallet += amount;
        await user.save();

        // Record transaction
        await Transaction.create({
            userId: user._id,
            type: 'deposit',
            amount,
            description: `Deposited $${amount}`
        });

        res.json({ 
            message: 'Deposit successful', 
            balance: user.wallet 
        });
    } catch (error) {
        res.status(500).json({ error: 'Deposit failed' });
    }
});

// Withdraw
app.post('/api/wallet/withdraw', auth, async (req, res) => {
    try {
        const { amount } = req.body;
        
        if (amount <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }

        const user = await User.findById(req.userId);
        
        if (user.wallet < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        user.wallet -= amount;
        await user.save();

        // Record transaction
        await Transaction.create({
            userId: user._id,
            type: 'withdraw',
            amount,
            description: `Withdrew $${amount}`
        });

        res.json({ 
            message: 'Withdrawal successful', 
            balance: user.wallet 
        });
    } catch (error) {
        res.status(500).json({ error: 'Withdrawal failed' });
    }
});

// ==================== ITEM ROUTES ====================

// Get all items
app.get('/api/items', async (req, res) => {
    try {
        const items = await Item.find().sort({ createdAt: -1 });
        res.json(items);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch items' });
    }
});

// Add item (Admin only)
app.post('/api/items', adminAuth, async (req, res) => {
    try {
        const { name, icon, description, price } = req.body;

        if (!name || !icon || !description || !price) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const item = new Item({
            name,
            icon,
            description,
            price,
            createdBy: req.user.username
        });

        await item.save();
        res.status(201).json(item);
    } catch (error) {
        console.error('Add item error:', error);
        res.status(500).json({ error: 'Failed to add item' });
    }
});

// Update item (Admin only)
app.put('/api/items/:id', adminAuth, async (req, res) => {
    try {
        const { name, icon, description, price } = req.body;
        
        const item = await Item.findByIdAndUpdate(
            req.params.id,
            { name, icon, description, price },
            { new: true }
        );

        if (!item) {
            return res.status(404).json({ error: 'Item not found' });
        }

        res.json(item);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update item' });
    }
});

// Delete item (Admin only)
app.delete('/api/items/:id', adminAuth, async (req, res) => {
    try {
        const item = await Item.findByIdAndDelete(req.params.id);
        
        if (!item) {
            return res.status(404).json({ error: 'Item not found' });
        }

        res.json({ message: 'Item deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete item' });
    }
});

// ==================== PURCHASE ROUTES ====================

// Buy item
app.post('/api/items/:id/buy', auth, async (req, res) => {
    try {
        const item = await Item.findById(req.params.id);
        
        if (!item) {
            return res.status(404).json({ error: 'Item not found' });
        }

        const user = await User.findById(req.userId);

        // Check balance
        if (user.wallet < item.price) {
            return res.status(400).json({ 
                error: 'Insufficient balance',
                required: item.price,
                balance: user.wallet
            });
        }

        // Deduct amount
        user.wallet -= item.price;
        await user.save();

        // Record purchase
        const purchase = new Purchase({
            userId: user._id,
            itemId: item._id,
            itemName: item.name,
            price: item.price
        });
        await purchase.save();

        // Record transaction
        await Transaction.create({
            userId: user._id,
            type: 'purchase',
            amount: item.price,
            itemId: item._id,
            description: `Purchased ${item.name} for $${item.price}`
        });

        res.json({
            message: 'Purchase successful',
            balance: user.wallet,
            purchase
        });
    } catch (error) {
        console.error('Purchase error:', error);
        res.status(500).json({ error: 'Purchase failed' });
    }
});

// Get user purchases
app.get('/api/user/purchases', auth, async (req, res) => {
    try {
        const purchases = await Purchase.find({ userId: req.userId })
            .sort({ purchaseDate: -1 });
        res.json(purchases);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch purchases' });
    }
});

// Get user transactions
app.get('/api/user/transactions', auth, async (req, res) => {
    try {
        const transactions = await Transaction.find({ userId: req.userId })
            .sort({ createdAt: -1 })
            .limit(50);
        res.json(transactions);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch transactions' });
    }
});

// ==================== ADMIN ROUTES ====================

// Get all users (Admin only)
app.get('/api/admin/users', adminAuth, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Get dashboard stats (Admin only)
app.get('/api/admin/stats', adminAuth, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({ role: 'user' });
        const totalItems = await Item.countDocuments();
        const totalPurchases = await Purchase.countDocuments();
        const totalRevenue = await Purchase.aggregate([
            { $group: { _id: null, total: { $sum: '$price' } } }
        ]);

        res.json({
            totalUsers,
            totalItems,
            totalPurchases,
            totalRevenue: totalRevenue[0]?.total || 0
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 5000;

app.listen(PORT, async () => {
    console.log(`🚀 Server running on port ${PORT}`);
    await initializeAdmin();
});
