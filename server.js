require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const PDFDocument = require('pdfkit'); 
const md5 = require('md5'); // ⚡ Required for PayHere Security
const path = require('path'); // <--- CRITICAL FIX 1: Import 'path' module
const app = express();

// --- 1. CONFIGURATION & MIDDLEWARE ---

// 👇 PAYHERE CREDENTIALS
const MERCHANT_ID = '1233636';       
const MERCHANT_SECRET = 'MzIxMDk2MTE2MDM3NDU2ODkxMjYxNTc4NzgyOTY0MjA0NTMxODM='; 

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ Connected to MongoDB Atlas"))
    .catch(err => console.error("❌ Connection Error", err));

// Set EJS as the templating engine
app.set('view engine', 'ejs');

// Allow the server to read data sent from HTML forms & JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // ⚡ Required for reading JSON from frontend fetch

// <--- CRITICAL FIX 2: Serve Static Files (Images/CSS)
app.use(express.static(path.join(__dirname, 'public'))); 
// ----------------------------------------------------

// Set up Sessions
app.use(session({
    secret: 'mysecretkey', 
    resave: false,
    saveUninitialized: false
}));


// --- 2. DATABASE MODELS ---

// User Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' }, // 'user' or 'admin'
    registeredAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Donation Schema
const donationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: Number,
    status: { type: String, default: 'pending' }, 
    transactionId: String,
    orderId: String, // Added to track PayHere Order ID
    date: { type: Date, default: Date.now }
});
const Donation = mongoose.model('Donation', donationSchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
    message: String,
    type: String, // 'success' (for money) or 'info' (for users)
    date: { type: Date, default: Date.now }
});
const Notification = mongoose.model('Notification', notificationSchema);


// --- 3. ROUTES ---

// Home Page
app.get('/', (req, res) => {
    res.render('index'); 
});

// --- AUTHENTICATION ---

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    try {
        await new User({ name, email, password: hashedPassword }).save();
        
        // 🔔 TRIGGER: Create Notification for Admin
        await new Notification({ 
            message: `🆕 New User Registered: ${name}`, 
            type: 'info' 
        }).save();

        res.redirect('/login');
    } catch (e) {
        console.log(e);
        res.send("Error: Email might already be taken.");
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.userId = user._id;
        req.session.role = user.role;
        
        if (user.role === 'admin') res.redirect('/admin');
        else res.redirect('/dashboard');
    } else {
        res.send("Invalid email or password");
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});


// --- USER FEATURES (DASHBOARD & PAYHERE PAYMENT) ---

app.get('/dashboard', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    
    const user = await User.findById(req.session.userId);
    // Sort donations by date (newest first)
    const donations = await Donation.find({ userId: req.session.userId }).sort({ date: -1 });
    
    res.render('dashboard', { user, donations });
});

// ⚡ NEW: Generate Security Hash for PayHere (Called by Frontend)
app.post('/get-hash', async (req, res) => {
    if (!req.session.userId) return res.status(401).send("Unauthorized");

    const { amount } = req.body;
    const orderId = "ORD-" + Date.now();
    
    // 1. Format the amount (Must be like 1000.00)
    let amountFormatted = parseFloat(amount).toLocaleString('en-us', {minimumFractionDigits: 2}).replaceAll(',', '');
    const currency = 'LKR';

    // 2. Hash the Secret (MD5 + Uppercase)
    let hashedSecret = md5(MERCHANT_SECRET).toUpperCase();

    // 3. Create the Final Hash: merchantID + orderID + amount + currency + hashedSecret
    let hashString = MERCHANT_ID + orderId + amountFormatted + currency + hashedSecret;
    let finalHash = md5(hashString).toUpperCase();

    // 4. Save Pending Donation in DB (So we can track it later)
    const newDonation = new Donation({
        userId: req.session.userId,
        amount: amount,
        status: 'pending',
        transactionId: 'PENDING',
        orderId: orderId
    });
    await newDonation.save();

    res.json({ 
        hash: finalHash,
        order_id: orderId,
        merchant_id: MERCHANT_ID
    });
});

// ⚡ NEW: Payment Success Return URL
app.get('/payment/success', async (req, res) => {
    const { order_id } = req.query;

    if (order_id) {
        // Fix for Localhost "Pending" issue
        await Donation.findOneAndUpdate(
            { orderId: order_id }, 
            { status: 'success', transactionId: order_id }
        );
        
        // 🔔 TRIGGER: Create Notification (with Rs.)
        // We find the donation again to get the amount and user details
        const donation = await Donation.findOne({ orderId: order_id }).populate('userId');
        if(donation){
             await new Notification({ 
                message: `💰 New Donation: Rs. ${donation.amount} from ${donation.userId ? donation.userId.name : 'Donor'}`, 
                type: 'success' 
            }).save();
        }
    }
    res.redirect('/dashboard');
});

// ⚡ NEW: Payment Notify URL (Webhook)
app.post('/payment/notify', async (req, res) => {
    const {
        merchant_id,
        order_id,
        payhere_amount,
        payhere_currency,
        status_code,
        md5sig
    } = req.body;

    // Verify the signature
    const localMd5sig = md5(
        merchant_id + 
        order_id + 
        payhere_amount + 
        payhere_currency + 
        status_code + 
        md5(MERCHANT_SECRET).toUpperCase()
    ).toUpperCase();

    if (localMd5sig === md5sig && status_code == 2) {
        // Find donation by Order ID and update status
        const donation = await Donation.findOne({ orderId: order_id }).populate('userId');
        
        if (donation) {
            donation.status = 'success';
            donation.transactionId = order_id; // Using OrderID as txn ID
            await donation.save();

            // 🔔 TRIGGER: Create Notification (UPDATED to Rs.)
            await new Notification({ 
                message: `💰 New Donation: Rs. ${donation.amount} from ${donation.userId ? donation.userId.name : 'Donor'}`, 
                type: 'success' 
            }).save();
        }
    }
    
    res.status(200).send('OK');
});


// 📄 GENERATE RECEIPT PDF (USER)
app.get('/receipt/:id', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');

    try {
        const donation = await Donation.findById(req.params.id).populate('userId');

        // Security Check: Only the user who made the donation can download the receipt
        if (!donation || donation.userId._id.toString() !== req.session.userId) {
            return res.status(403).send("Unauthorized Access");
        }

        const doc = new PDFDocument({ size: 'A4', margin: 50 });

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=Receipt-${donation.transactionId}.pdf`);

        doc.pipe(res);

        doc.fontSize(20).text('OFFICIAL DONATION RECEIPT', { align: 'center' });
        doc.moveDown();
        doc.fontSize(10).text('---------------------------------------------------------', { align: 'center' });
        doc.moveDown();
        doc.fontSize(12).text(`Date: ${donation.date.toDateString()}`);
        doc.text(`Transaction ID: ${donation.transactionId}`);
        doc.moveDown();
        doc.fontSize(14).text(`Donor Name: ${donation.userId.name}`);
        doc.text(`Donor Email: ${donation.userId.email}`);
        doc.moveDown();
        // UPDATED: Changed $ to Rs.
        doc.fontSize(16).font('Helvetica-Bold').text(`Amount Donated: Rs. ${donation.amount}`, { align: 'center' });
        doc.moveDown(2);
        doc.fontSize(10).font('Helvetica').text('Thank you for supporting our cause!', { align: 'center' });
        doc.text('This is a computer-generated receipt.', { align: 'center' });
        doc.end();

    } catch (err) {
        console.error(err);
        res.send("Error generating receipt");
    }
});


// --- SETTINGS ROUTES ---

app.get('/settings', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    const user = await User.findById(req.session.userId);
    res.render('settings', { user, message: null });
});

app.post('/settings', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    const { name, newPassword } = req.body;
    const user = await User.findById(req.session.userId);

    if (name) user.name = name;
    if (newPassword && newPassword.trim() !== "") {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
    }

    await user.save();
    res.render('settings', { user, message: "✅ Profile Updated Successfully!" });
});


// --- ADMIN FEATURES (DASHBOARD, REPORTS, SORTS) ---

app.get('/admin', async (req, res) => {
    if (req.session.role !== 'admin') return res.send("Access Denied: Admins Only");
    
    // 1. FILTER LOGIC
    let userFilter = {};
    if (req.query.role && req.query.role !== 'all') {
        userFilter.role = req.query.role; 
    }
    
    // 2. SORT LOGIC
    const sortBy = req.query.sortBy || 'dateDesc';
    let sortQuery = {};
    if (sortBy === 'dateDesc') sortQuery = { date: -1 };
    else if (sortBy === 'dateAsc') sortQuery = { date: 1 };
    else if (sortBy === 'amountDesc') sortQuery = { amount: -1 };
    else if (sortBy === 'amountAsc') sortQuery = { amount: 1 };

    // 3. FETCH DATA
    const users = await User.find(userFilter);
    const donations = await Donation.find({}).populate('userId', 'name email').sort(sortQuery); 
    
    // 🔔 Fetch Last 5 Notifications
    const notifications = await Notification.find().sort({ date: -1 }).limit(5);
    
    // 4. CHART DATA LOGIC
    const allDonationsForCharts = await Donation.find({});
    const last30DaysLabels = [], last30DaysData = [], last7DaysLabels = [], last7DaysData = [];
    const today = new Date();
    
    for (let i = 29; i >= 0; i--) {
        const d = new Date();
        d.setDate(today.getDate() - i);
        const dateString = d.toDateString(); 

        const dailyTotal = allDonationsForCharts.reduce((acc, curr) => {
            if (curr.status === 'success' && curr.date.toDateString() === dateString) {
                return acc + curr.amount;
            }
            return acc;
        }, 0);

        last30DaysLabels.push(d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })); 
        last30DaysData.push(dailyTotal);

        if (i < 7) {
            last7DaysLabels.push(d.toLocaleDateString('en-US', { weekday: 'short' }));
            last7DaysData.push(dailyTotal);
        }
    }

    const totalDonations = allDonationsForCharts.reduce((acc, curr) => 
        curr.status === 'success' ? acc + curr.amount : acc, 0);

    res.render('admin', { 
        users, 
        donations, 
        totalDonations, 
        notifications,
        currentFilter: req.query.role || 'all',
        currentSort: sortBy, 
        chartData: {
            days30: { labels: last30DaysLabels, data: last30DaysData },
            days7: { labels: last7DaysLabels, data: last7DaysData }
        }
    });
});

// Clear Notifications
app.get('/admin/clear-notifications', async (req, res) => {
    if (req.session.role !== 'admin') return res.redirect('/login');
    await Notification.deleteMany({});
    res.redirect('/admin');
});

// 📄 NEW: GENERATE ADMIN PDF REPORT
app.get('/admin/report-pdf', async (req, res) => {
    if (req.session.role !== 'admin') return res.send("Access Denied");

    const donations = await Donation.find({}).populate('userId').sort({ date: -1 });
    const doc = new PDFDocument({ margin: 30 });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename=Admin_Donation_Report.pdf');

    doc.pipe(res);

    // --- PDF DESIGN ---
    doc.fontSize(18).text('Admin Donation Report', { align: 'center' });
    doc.fontSize(12).text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
    doc.moveDown();
    doc.text('--------------------------------------------------------------------------', { align: 'center' });
    doc.moveDown();

    // Table Header
    let y = doc.y;
    doc.font('Helvetica-Bold').fontSize(10);
    doc.text('Date', 50, y);
    doc.text('Donor Name', 150, y);
    // UPDATED: Changed $ to Rs.
    doc.text('Amount (Rs.)', 350, y);
    doc.text('Status', 450, y);
    doc.moveDown();

    // Table Rows
    doc.font('Helvetica').fontSize(10);
    donations.forEach(d => {
        y = doc.y;
        if(y > 700) { doc.addPage(); y = 50; } 
        const donorName = d.userId ? d.userId.name : 'Unknown';
        const dateStr = d.date.toISOString().split('T')[0];

        doc.text(dateStr, 50, y);
        doc.text(donorName, 150, y);
        doc.text(d.amount.toString(), 350, y);
        
        if(d.status === 'success') doc.fillColor('green');
        else doc.fillColor('red');
        
        doc.text(d.status.toUpperCase(), 450, y);
        doc.fillColor('black');
        doc.moveDown(0.5);
    });
    doc.end();
});

// Export Users to CSV
app.get('/admin/export', async (req, res) => {
    if (req.session.role !== 'admin') return res.send("Access Denied");
    const users = await User.find({});
    let csvContent = "Name,Email,Role,Registered Date\n"; 
    users.forEach(user => {
        const date = user.registeredAt.toISOString().split('T')[0];
        csvContent += `${user.name},${user.email},${user.role},${date}\n`;
    });
    res.header('Content-Type', 'text/csv');
    res.attachment('users_list.csv');
    res.send(csvContent);
});

// --- START SERVER ---
app.listen(3000, () => {
    console.log("🚀 Server running on http://localhost:3000");
});