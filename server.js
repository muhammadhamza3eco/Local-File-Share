const express = require('express');
const session = require('express-session'); // Added
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto'); // Added for salt generation
const argon2 = require('argon2'); // Use the correct argon2 package
const packageJson = require('./package.json'); // Read package.json

const app = express();
const port = 8080; // Changed port from 3001 due to EADDRINUSE error
const userFilesBaseDir = path.join(__dirname, 'user_files'); // Renamed base directory
const usersFilePath = path.join(__dirname, 'users.json'); // Path for user data

const logFilePath = path.join(__dirname, 'activity.log');

// Simple logging function (now includes request object for IP and username)
function logActivity(req, actionMessage) {
    const timestamp = new Date().toISOString();
    // Get IP address - req.ip is preferred in Express
    // Use 'unknown' if IP is not available for some reason
    const ip = req ? (req.ip || req.connection?.remoteAddress || 'unknown') : 'unknown';
    // Get username if available
    const username = req && req.session && req.session.user ? req.session.user.username : 'system';

    // Convert absolute paths to relative paths in the action message
    let formattedMessage = actionMessage;

    // Check if the message contains an absolute path to the user files directory
    if (formattedMessage.includes(userFilesBaseDir)) {
        // Replace absolute path with relative path
        formattedMessage = formattedMessage.replace(new RegExp(userFilesBaseDir.replace(/\\/g, '\\\\') + '\\\\([^\\\\]+)\\\\(private|public)\\\\', 'g'), '/$1/$2/');
        // Replace Windows backslashes with forward slashes for consistency
        formattedMessage = formattedMessage.replace(/\\/g, '/');
    }

    // Include username in log message
    const logMessage = `${timestamp} [${ip}] [${username}] - ${formattedMessage}\n`;

    // Write to main activity log
    fs.appendFile(logFilePath, logMessage, (err) => {
        if (err) {
            console.error("Failed to write to activity log:", err);
        }
    });

    // If username is available, also write to user-specific log
    if (username !== 'system') {
        // Create user logs directory if it doesn't exist
        const userLogsDir = path.join(__dirname, 'user_logs');
        if (!fs.existsSync(userLogsDir)) {
            fs.mkdirSync(userLogsDir, { recursive: true });
        }

        // Write to user-specific log file
        const userLogPath = path.join(userLogsDir, `${username}.log`);
        fs.appendFile(userLogPath, logMessage, (err) => {
            if (err) {
                console.error(`Failed to write to user log for ${username}:`, err);
            }
        });
    }

    // Log to console as well, including IP and username
    console.log(`[${ip}] [${username}] ${actionMessage}`);
}

// Pagination utility function
function paginateArray(array, page, itemsPerPage) {
    const startIndex = (page - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;

    const paginatedItems = array.slice(startIndex, endIndex);

    const totalPages = Math.ceil(array.length / itemsPerPage);

    return {
        items: paginatedItems,
        pagination: {
            totalItems: array.length,
            itemsPerPage: itemsPerPage,
            currentPage: page,
            totalPages: totalPages,
            hasNextPage: page < totalPages,
            hasPrevPage: page > 1
        }
    };
}

// Ensure the base user files directory exists
if (!fs.existsSync(userFilesBaseDir)) { // Fix: Use userFilesBaseDir
    fs.mkdirSync(userFilesBaseDir);
    // No request object available here, so pass null
    logActivity(null, `Created base user files directory: ${userFilesBaseDir}`); // Fix: Use userFilesBaseDir
}

// --- User Data Handling ---
let users = {}; // In-memory store, loaded from file

// Load users from JSON file
function loadUsers() {
    try {
        if (fs.existsSync(usersFilePath)) {
            const data = fs.readFileSync(usersFilePath, 'utf8');
            users = JSON.parse(data);
            console.log('User data loaded successfully.');
        } else {
            console.log('users.json not found, starting with empty user list.');
            saveUsers(); // Create the file if it doesn't exist
        }
    } catch (err) {
        console.error('Error loading or parsing users.json:', err);
        // Start with empty users if file is corrupt
        users = {};
    }
    // Ensure all loaded users have optional fields initialized if missing
    for (const username in users) {
        if (!users[username].name) users[username].name = '';
        if (!users[username].location) users[username].location = '';
    }
}

// Save users to JSON file
function saveUsers() {
    try {
        fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2), 'utf8');
    } catch (err) {
        console.error('Error saving users.json:', err);
    }
}

// Load users on server start
loadUsers();

// --- End User Data Handling ---

// --- Path Helper ---
// Gets the absolute path for a user's file/folder and performs security checks.
// relativePath should be relative to the user's private or public root.
function getUserScopedPath(username, type = 'private', relativePath = '') {
    if (!username) throw new Error("Username is required for getUserScopedPath");

    const userRoot = path.join(userFilesBaseDir, username);
    const scopeRoot = path.join(userRoot, type === 'public' ? 'public' : 'private');

    // Sanitize relativePath to prevent directory traversal (e.g., '../..')
    // path.join normalizes, but we need to ensure it stays within the scopeRoot
    const absolutePath = path.join(scopeRoot, relativePath);

    // Security Check: Ensure the final path is within the intended scope root
    if (!absolutePath.startsWith(scopeRoot)) {
        console.error(`Security Alert: Path traversal attempt detected. User: ${username}, Type: ${type}, Path: ${relativePath}, Resolved: ${absolutePath}`);
        throw new Error("Invalid path: Attempted directory traversal.");
    }
     // Security Check: Ensure the path is also within the overall user directory
     if (!absolutePath.startsWith(userRoot)) {
         console.error(`Security Alert: Path somehow escaped user directory. User: ${username}, Path: ${absolutePath}`);
         throw new Error("Invalid path: Escaped user directory.");
     }


    return absolutePath;
}
// --- End Path Helper ---


// --- Middleware Setup ---
// IMPORTANT: Middleware order matters!

// Parse URL-encoded bodies (form data)
app.use(express.urlencoded({ extended: true }));

// Session Configuration (MUST come before routes that use sessions)
app.use(session({
    secret: 'your secret key', // CHANGE THIS to a strong random string
    resave: false,
    saveUninitialized: false, // Don't save sessions until something is stored
    cookie: {
        // secure: true, // Uncomment this in production when using HTTPS
        httpOnly: true, // Helps prevent XSS attacks
        maxAge: 1000 * 60 * 60 * 24 // Session duration (e.g., 1 day)
    }
}));

// Serve static files (CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));

// Set EJS view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- End Middleware Setup ---


// --- Auth Routes ---

// GET /signup - Display signup page
app.get('/signup', (req, res) => {
    res.render('signup');
});

// POST /signup - Handle user registration
app.post('/signup', async (req, res) => {
    const { username, password, confirmPassword } = req.body;

    if (!username || !password || !confirmPassword) {
        return res.render('signup', { error: 'All fields are required.' });
    }
    if (password !== confirmPassword) {
        return res.render('signup', { error: 'Passwords do not match.' });
    }
    if (users[username]) {
        return res.render('signup', { error: 'Username already exists.' });
    }

    try {
        // Hash password using Argon2 (standard Node.js API)
        // It typically returns the full hash string including salt and params
        const passwordHash = await argon2.hash(password, {
             type: argon2.argon2id, // Recommended type
             salt: crypto.randomBytes(16)
         });

        // Store user (username as key, hash and optional fields)
        users[username] = {
            hash: passwordHash,
            name: '', // Initialize optional fields
            location: ''
        };

        // Create user directories
        const userDir = path.join(userFilesBaseDir, username);
        const privateDir = path.join(userDir, 'private');
        const publicDir = path.join(userDir, 'public');

        // Use promises for cleaner async directory creation
        await fs.promises.mkdir(privateDir, { recursive: true });
        await fs.promises.mkdir(publicDir, { recursive: true });

        saveUsers(); // Persist user data to file AFTER directories are likely created

        logActivity(req, `New user signed up: ${username}. Directories created.`);

        // Automatically log in the user after signup
        req.session.user = { username: username };
        res.redirect('/'); // Redirect to the main file share page

    } catch (err) {
        console.error('Error during signup hashing:', err);
        res.render('signup', { error: 'An error occurred during signup. Please try again.' });
    }
});


// GET /login - Display login page
app.get('/login', (req, res) => {
     // If already logged in, redirect to main page
    if (req.session.user) {
        return res.redirect('/');
    }
    res.render('login');
});

// POST /login - Handle user login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.render('login', { error: 'Username and password are required.' });
    }

    const user = users[username];
    if (!user) {
        return res.render('login', { error: 'Invalid username or password.' });
    }

    try {
        // Verify password using Argon2 (standard Node.js API)
        // Pass the stored hash string directly
        const correctPassword = await argon2.verify(user.hash, password);

        if (correctPassword) {
            logActivity(req, `User logged in: ${username}`);
            req.session.user = { username: username }; // Store user info in session
            res.redirect('/'); // Redirect to main page
        } else {
            res.render('login', { error: 'Invalid username or password.' });
        }
    } catch (err) {
        console.error('Error during login verification:', err);
        res.render('login', { error: 'An error occurred during login. Please try again.' });
    }
});

// GET /logout - Handle user logout
app.get('/logout', (req, res) => {
    if (req.session.user) {
         logActivity(req, `User logged out: ${req.session.user.username}`);
        req.session.destroy((err) => {
            if (err) {
                console.error("Error destroying session:", err);
                return res.redirect('/'); // Redirect anyway, but log error
            }
            res.clearCookie('connect.sid'); // Clear the session cookie
            res.redirect('/login'); // Redirect to login page
        });
    } else {
        res.redirect('/login');
    }
});

// --- End Auth Routes ---


// --- Middleware to Protect Routes ---
function ensureAuthenticated(req, res, next) {
    if (req.session.user) {
        return next(); // User is logged in, proceed
    } else {
        res.redirect('/login'); // Not logged in, redirect to login
    }
}
// --- End Middleware ---


// --- Public File Access Route ---
// This route should come *before* the ensureAuthenticated middleware
// :filepath(*) allows the path to contain slashes
app.get('/public/:username/:filepath(*)', (req, res) => {
    const { username, filepath } = req.params;

    if (!username || typeof filepath === 'undefined') { // Check filepath presence
        return res.status(400).send('Username and filepath are required.');
    }

    try {
        // Construct path within the user's public directory
        const publicPath = getUserScopedPath(username, 'public', filepath);

        // Check if it exists and is a file
        fs.stat(publicPath, (statErr, stats) => {
            if (statErr) {
                if (statErr.code === 'ENOENT') {
                    return res.status(404).send('Public file not found.');
                }
                console.error(`Error stating public file: ${publicPath}`, statErr);
                return res.status(500).send('Error accessing public file.');
            }

            if (!stats.isFile()) {
                // Don't allow listing public directories directly for simplicity/security
                return res.status(403).send('Access denied.');
            }

            // Send the file for viewing/download
            // Use res.sendFile for better content-type handling than res.download
            res.sendFile(publicPath, (sendErr) => {
                 if (sendErr) {
                     console.error(`Error sending public file: ${publicPath}`, sendErr);
                     // Avoid sending another response if headers already sent
                     if (!res.headersSent) {
                         res.status(500).send('Error sending file.');
                     }
                 } else {
                     // Optional: Log public access (could be noisy)
                     // logActivity(req, `Accessed public file: User ${username}, File ${filepath}`);
                 }
            });
        });

    } catch (err) { // Catch errors from getUserScopedPath
        console.error(`Error in GET /public handler:`, err);
        res.status(err.message.includes("Invalid path") ? 400 : 500).send(err.message || 'Error processing public file request.');
    }
});
// --- End Public File Access Route ---


// Configure Multer for file uploads
const upload = multer({
    storage: multer.diskStorage({
        destination: function (req, file, cb) {
            try {
                // Save to user's private directory, potentially within a subfolder
                const relativeDestDir = req.body.currentDir || ''; // Relative path from form
                const absoluteDestDir = getUserScopedPath(req.session.user.username, 'private', relativeDestDir);

                // Ensure the target directory exists within the user's private scope
                fs.mkdir(absoluteDestDir, { recursive: true }, (err) => {
                     if (err) {
                         console.error("Error ensuring upload directory exists:", err);
                         return cb(new Error("Failed to create upload directory."));
                     }
                     cb(null, absoluteDestDir); // Pass absolute path to multer
                 });
            } catch (err) {
                 console.error("Error resolving upload destination:", err);
                 return cb(new Error("Invalid upload destination path."));
            }
        },
        filename: function (req, file, cb) {
            cb(null, file.originalname);
        }
    })
});


// --- Main File Share Routes (Now Protected) ---

// Apply authentication middleware to all routes below this point
// EXCEPT static files (already configured) and auth routes (above)
app.use(ensureAuthenticated);


// Route to display files and folders (User's Private Scope)
app.get('/', async (req, res) => { // ensureAuthenticated applied via app.use
    const username = req.session.user.username;
    const currentRelativeDir = req.query.dir || ''; // Relative to user's private root
    const page = parseInt(req.query.page) || 1; // Current page, default to 1
    const itemsPerPage = 10; // Number of items per page

    try { // Outer try for getUserScopedPath
        const currentDir = getUserScopedPath(username, 'private', currentRelativeDir);
        const parentDir = currentRelativeDir ? path.dirname(currentRelativeDir) : null;

        // Read directory contents
        fs.readdir(currentDir, { withFileTypes: true }, async (err, dirEntries) => { // Inner async callback
        if (err) {
            console.error("Error reading directory:", err);
            if (err.code === 'ENOENT') {
                return res.status(404).send('Directory not found.');
            }
            return res.status(500).send('Error reading directory');
        }

        // Get stats and check public status for each entry
        const filesDataPromises = dirEntries.map(async (entry) => {
            try {
                const fullEntryPath = path.join(currentDir, entry.name); // Absolute path in private dir
                const stats = await fs.promises.stat(fullEntryPath);
                const relativeEntryPath = path.join(currentRelativeDir, entry.name);

                let isPublic = false;
                if (!entry.isDirectory()) {
                    // Check if the corresponding file exists in the public directory
                    try {
                        const publicFilePath = getUserScopedPath(username, 'public', relativeEntryPath);
                        isPublic = fs.existsSync(publicFilePath);
                    } catch (publicPathError) {
                        // Ignore errors checking public path (e.g., traversal attempts)
                        console.warn(`Could not check public status for ${relativeEntryPath}: ${publicPathError.message}`);
                    }
                }

                return {
                    name: entry.name,
                    isDirectory: entry.isDirectory(),
                    path: relativeEntryPath, // Path relative to user's private root
                    mtime: stats.mtime,
                    isPublic: isPublic, // Add flag indicating public status
                    size: stats.size // Add file size in bytes
                };
            } catch (statErr) {
                console.error(`Error getting stats for ${entry.name}:`, statErr);
                return {
                    name: entry.name,
                    isDirectory: entry.isDirectory(),
                    path: path.join(currentRelativeDir, entry.name),
                    mtime: null,
                    isPublic: false, // Assume not public if stats fail
                    size: 0 // Default size to 0 if stats fail
                };
            }
        });

        const filesData = await Promise.all(filesDataPromises);

        // Sort directories first, then files, alphabetically
        filesData.sort((a, b) => {
            if (a.isDirectory && !b.isDirectory) return -1;
            if (!a.isDirectory && b.isDirectory) return 1;
            return a.name.localeCompare(b.name);
        });

        // Apply pagination
        const paginatedData = paginateArray(filesData, page, itemsPerPage);

        let parentDirLink = null;
        if (parentDir !== null && parentDir !== '.') {
            parentDirLink = `/?dir=${encodeURIComponent(parentDir)}`;
        } else if (currentRelativeDir) { // Link to root if we are in a subdirectory but parent is '.'
            parentDirLink = `/`;
        }

        // Render the EJS template
        // Function to format file size in a human-readable format
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        res.render('index', {
            files: paginatedData.items,
            pagination: paginatedData.pagination,
            currentRelativeDir: currentRelativeDir,
            parentDirLink: parentDirLink,
            username: req.session.user.username, // Pass username to view
            userIp: req.ip || req.connection?.remoteAddress || 'unknown', // Pass user IP
            formatFileSize: formatFileSize, // Pass the format function to the view
            appVersion: packageJson.version // Pass app version
        });
    }); // End fs.readdir callback
    } catch (err) { // Catch errors from getUserScopedPath or other sync issues
        console.error(`Error in GET / handler for user ${username}:`, err);
        res.status(err.message.includes("Invalid path") ? 400 : 500).send(err.message || 'Error accessing directory.');
    }
});

// Route to download a file (from user's private scope)
app.get('/download', (req, res) => { // ensureAuthenticated applied via app.use
    const username = req.session.user.username;
    const requestedRelativePath = req.query.file; // Relative to user's private root

    if (!requestedRelativePath) {
        return res.status(400).send('No file specified.');
    }

    try {
        const fullPath = getUserScopedPath(username, 'private', requestedRelativePath);

        // Check if file exists and is a file (fs.stat is async)
        fs.stat(fullPath, (err, stats) => { // Start fs.stat callback
            if (err) {
                console.error("Error accessing file:", err);
                return res.status(404).send('File not found.');
            }
            if (!stats.isFile()) {
                return res.status(400).send('Path is not a file.');
            }

            res.download(fullPath, (downloadErr) => { // Start res.download callback
                if (downloadErr) {
                    // Avoid logging benign errors like user cancellation
                    if (!res.headersSent) { // Check if headers were already sent (e.g., user cancelled)
                         console.error("Error downloading file:", downloadErr);
                         // Don't try to send another response if headers already sent
                         try { res.status(500).send('Error downloading file.'); } catch(e){}
                    }
                } else {
                     // Use relative path for logging
                     const relativeFilePath = requestedRelativePath;
                     logActivity(req, `Downloaded file: ${relativeFilePath}`);
                }
            }); // End res.download callback
        }); // End fs.stat callback
    } catch (err) { // Catch errors from getUserScopedPath
        console.error(`Error in GET /download handler for user ${username}:`, err);
        res.status(err.message.includes("Invalid path") ? 400 : 500).send(err.message || 'Error processing download request.');
    }
});

// Route to handle file uploads
// Apply ensureAuthenticated specifically here before multer runs
app.post('/upload', ensureAuthenticated, upload.single('fileToUpload'), (req, res) => {
    // 'fileToUpload' is the name attribute from the input type="file"
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }

    // Get relative path for logging
    const relativeUploadPath = req.body.currentDir ?
        path.join(req.body.currentDir, req.file.originalname) :
        req.file.originalname;
    logActivity(req, `Uploaded file: ${relativeUploadPath}`);
    // Redirect back to the directory where the file was uploaded
    const redirectDir = req.body.currentDir ? `/?dir=${encodeURIComponent(req.body.currentDir)}` : '/';
    res.redirect(redirectDir);
});


// Route to handle folder creation (in user's private scope)
app.post('/create-folder', (req, res) => { // ensureAuthenticated applied via app.use
    const username = req.session.user.username;
    const currentRelativeDir = req.body.currentDir || ''; // Relative to user's private root
    const newFolderName = req.body.folderName;

    if (!newFolderName) {
        return res.status(400).send('Folder name is required.');
    }

    const sanitizedFolderName = newFolderName.replace(/[\\/.]/g, '_'); // Replace slashes and dots
     if (!sanitizedFolderName || sanitizedFolderName === '.' || sanitizedFolderName === '..') {
         logActivity(req, `Attempted invalid folder name: ${newFolderName}`);
         return res.status(400).send('Invalid folder name.');
    }

    try {
        const newFolderPath = getUserScopedPath(username, 'private', path.join(currentRelativeDir, sanitizedFolderName));

        // fs.mkdir is async
        fs.mkdir(newFolderPath, { recursive: false }, (err) => { // Start fs.mkdir callback
            if (err) {
                if (err.code === 'EEXIST') {
                     // Use relative path for logging
                     const relativeFolderPath = path.join(currentRelativeDir, sanitizedFolderName);
                     logActivity(req, `Attempted to create existing folder: ${relativeFolderPath}`);
                } else {
                    console.error("Error creating folder:", err);
                    // Don't try to redirect if headers might be sent on error
                    return res.status(500).send('Error creating folder.');
                }
            } else {
                 // Use relative path for logging
                 const relativeFolderPath = path.join(currentRelativeDir, sanitizedFolderName);
                 logActivity(req, `Created folder: ${relativeFolderPath}`);
            }
            // Redirect back to the directory where the folder was created
            const redirectDir = currentRelativeDir ? `/?dir=${encodeURIComponent(currentRelativeDir)}` : '/';
            // Ensure redirect happens only once and after potential errors handled
             if (!res.headersSent) {
                res.redirect(redirectDir);
            }
        }); // End fs.mkdir callback
    } catch (err) { // Catch errors from getUserScopedPath
        console.error(`Error in POST /create-folder handler for user ${username}:`, err);
        res.status(err.message.includes("Invalid path") ? 400 : 500).send(err.message || 'Error processing folder creation.');
    }
});

// Route to handle file/folder deletion (from user's private scope)
app.post('/delete', (req, res) => { // ensureAuthenticated applied via app.use
    const username = req.session.user.username;
    const itemPathRelative = req.body.itemPath; // Relative to user's private root
    const currentRelativeDir = req.body.currentDir || ''; // For redirecting

    if (!itemPathRelative) {
        return res.status(400).send('No item path specified for deletion.');
    }

     // Prevent deleting root private/public folders (safeguard)
     if (itemPathRelative === '' || itemPathRelative === '/' || itemPathRelative === '.') {
         logActivity(req, `Attempt blocked to delete root folder for user ${username}`);
         return res.status(400).send('Cannot delete the root directory.');
     }


    try {
        const fullPath = getUserScopedPath(username, 'private', itemPathRelative);

        // fs.stat is async
        fs.stat(fullPath, (err, stats) => { // Start fs.stat callback
            if (err) {
                if (err.code === 'ENOENT') {
                    logActivity(req, `Attempted to delete non-existent item: ${itemPathRelative}`);
                    // Item might have been deleted already, redirect gracefully
                    const redirectDir = currentRelativeDir ? `/?dir=${encodeURIComponent(currentRelativeDir)}` : '/';
                     if (!res.headersSent) { return res.redirect(redirectDir); } else { return; } // Prevent multiple responses
                }
                console.error("Error accessing item for deletion:", err);
                 if (!res.headersSent) { return res.status(500).send('Error accessing item for deletion.'); } else { return; }
            }

            const deleteAction = stats.isDirectory()
                ? fs.rm // Use fs.rm for modern Node.js (handles non-empty dirs)
                : fs.unlink; // Use fs.unlink for files

            // Call the appropriate delete function with correct arguments
            if (stats.isDirectory()) {
                // fs.rm takes options
                fs.rm(fullPath, { recursive: true, force: true }, (deleteErr) => { // Start fs.rm callback
                    handleDeleteCallback(deleteErr, stats.isDirectory(), fullPath, req, res, currentRelativeDir, itemPathRelative); // Pass itemPathRelative
                });
            } else {
                // fs.unlink does NOT take options, only path and callback
                fs.unlink(fullPath, (deleteErr) => { // Start fs.unlink callback
                    handleDeleteCallback(deleteErr, stats.isDirectory(), fullPath, req, res, currentRelativeDir, itemPathRelative); // Pass itemPathRelative
                });
            }
        }); // End fs.stat callback
    } catch (err) { // Catch errors from getUserScopedPath
        console.error(`Error in POST /delete handler for user ${username}:`, err);
        res.status(err.message.includes("Invalid path") ? 400 : 500).send(err.message || 'Error processing deletion.');
    }
});

// Helper function to handle the callback for both fs.rm and fs.unlink
function handleDeleteCallback(deleteErr, isDirectory, fullPath, req, res, currentRelativeDir, itemPathRelative) { // Added itemPathRelative
    if (deleteErr) {
        console.error(`Error deleting ${isDirectory ? 'directory' : 'file'} from private scope:`, deleteErr);
         if (!res.headersSent) { return res.status(500).send(`Error deleting ${isDirectory ? 'directory' : 'file'}.`); } else { return; }
    }

    // Log successful deletion from private scope
     logActivity(req, `Deleted ${isDirectory ? 'directory' : 'file'} from private scope: ${itemPathRelative}`); // Pass req

    // If it was a file, attempt to delete the corresponding public file
    if (!isDirectory && itemPathRelative) {
        try {
            const username = req.session.user.username;
            const publicPath = getUserScopedPath(username, 'public', itemPathRelative);

            // Check if public file exists and delete it
            fs.access(publicPath, fs.constants.F_OK, (accessErr) => {
                if (!accessErr) {
                    // Public file exists, attempt to delete it
                    fs.unlink(publicPath, (unlinkPublicErr) => {
                        if (unlinkPublicErr) {
                            console.error(`Error deleting corresponding public file ${publicPath}:`, unlinkPublicErr);
                            // Log the error but don't block the redirect for the private deletion
                        } else {
                            logActivity(req, `Automatically unshared (deleted public file): ${itemPathRelative}`);
                        }
                        // Redirect after attempting public deletion (or if it didn't exist)
                        redirectToParent();
                    });
                } else {
                     // Public file doesn't exist, just redirect
                     redirectToParent();
                }
            });
        } catch (publicPathError) {
             console.error(`Error constructing public path for auto-unshare: ${publicPathError.message}`);
             // Redirect even if public path check fails
             redirectToParent();
        }
    } else {
        // If it was a directory or itemPathRelative is missing, just redirect
        redirectToParent();
    }

    // Helper function for redirection
    function redirectToParent() {
        const redirectDir = currentRelativeDir ? `/?dir=${encodeURIComponent(currentRelativeDir)}` : '/';
        if (!res.headersSent) {
            res.redirect(redirectDir);
        }
    }
}

// Route to handle sharing a file publicly
app.post('/share', (req, res) => { // ensureAuthenticated applied via app.use
    const username = req.session.user.username;
    const itemPathRelative = req.body.itemPath; // Relative to user's private root
    const currentRelativeDir = req.body.currentDir || ''; // For redirecting

    if (!itemPathRelative) {
        return res.status(400).send('No item path specified for sharing.');
    }

    try {
        const privatePath = getUserScopedPath(username, 'private', itemPathRelative);
        const publicPath = getUserScopedPath(username, 'public', itemPathRelative); // Get corresponding public path

        // Ensure the source is a file
        fs.stat(privatePath, (statErr, stats) => {
            if (statErr) {
                console.error(`Error stating file for sharing: ${privatePath}`, statErr);
                return res.status(404).send('File not found or inaccessible.');
            }
            if (!stats.isFile()) {
                return res.status(400).send('Only files can be shared.');
            }

            // Ensure the public destination directory exists
            const publicDir = path.dirname(publicPath);
            fs.mkdir(publicDir, { recursive: true }, (mkdirErr) => {
                 if (mkdirErr) {
                     console.error(`Error ensuring public directory exists: ${publicDir}`, mkdirErr);
                     return res.status(500).send('Error preparing public share location.');
                 }

                 // Copy the file from private to public
                 fs.copyFile(privatePath, publicPath, (copyErr) => {
                     if (copyErr) {
                         console.error(`Error copying file to public: ${privatePath} -> ${publicPath}`, copyErr);
                         return res.status(500).send('Error sharing file.');
                     }

                     logActivity(req, `Shared file publicly: User ${username}, File ${itemPathRelative}`);

                     // Redirect back to the private directory view
                     const redirectDir = currentRelativeDir ? `/?dir=${encodeURIComponent(currentRelativeDir)}` : '/';
                     res.redirect(redirectDir);
                 });
            });
        });

    } catch (err) { // Catch errors from getUserScopedPath
        console.error(`Error in POST /share handler for user ${username}:`, err);
        res.status(err.message.includes("Invalid path") ? 400 : 500).send(err.message || 'Error processing share request.');
    }
});

// Route to handle unsharing a file (making it private)
app.post('/unshare', (req, res) => { // ensureAuthenticated applied via app.use
    const username = req.session.user.username;
    const itemPathRelative = req.body.itemPath; // Relative to user's private/public root
    const currentRelativeDir = req.body.currentDir || ''; // For redirecting

    if (!itemPathRelative) {
        return res.status(400).send('No item path specified for unsharing.');
    }

    try {
        const publicPath = getUserScopedPath(username, 'public', itemPathRelative);

        // Check if the public file exists before attempting deletion
        fs.stat(publicPath, (statErr, stats) => {
            if (statErr) {
                if (statErr.code === 'ENOENT') {
                    // File is already not public, maybe UI was out of sync
                    logActivity(req, `Attempted to unshare non-public file: User ${username}, File ${itemPathRelative}`);
                    const redirectDir = currentRelativeDir ? `/?dir=${encodeURIComponent(currentRelativeDir)}` : '/';
                    return res.redirect(redirectDir);
                }
                // Other error accessing the file
                console.error(`Error stating public file for unsharing: ${publicPath}`, statErr);
                return res.status(500).send('Error accessing file to unshare.');
            }

            if (!stats.isFile()) {
                 // Should not happen if sharing only allows files, but good to check
                 return res.status(400).send('Cannot unshare a directory.');
            }

            // Delete the file from the public directory
            fs.unlink(publicPath, (unlinkErr) => {
                if (unlinkErr) {
                    console.error(`Error deleting public file for unsharing: ${publicPath}`, unlinkErr);
                    return res.status(500).send('Error making file private.');
                }

                logActivity(req, `Unshared file (made private): User ${username}, File ${itemPathRelative}`);

                // Redirect back to the private directory view
                const redirectDir = currentRelativeDir ? `/?dir=${encodeURIComponent(currentRelativeDir)}` : '/';
                res.redirect(redirectDir);
            });
        });

    } catch (err) { // Catch errors from getUserScopedPath
        console.error(`Error in POST /unshare handler for user ${username}:`, err);
        res.status(err.message.includes("Invalid path") ? 400 : 500).send(err.message || 'Error processing unshare request.');
    }
});

// Route to view user's activity log
app.get('/activity-log', (req, res) => { // ensureAuthenticated applied via app.use
    const username = req.session.user.username;
    const page = parseInt(req.query.page) || 1; // Current page, default to 1
    const itemsPerPage = 15; // Number of items per page

    try {
        const userLogPath = path.join(__dirname, 'user_logs', `${username}.log`);

        // Check if the log file exists
        if (!fs.existsSync(userLogPath)) {
            return res.render('activity-log', {
                username: username,
                userIp: req.ip || req.connection?.remoteAddress || 'unknown', // Pass user IP
                entries: [],
                pagination: null, // Pass null pagination if no entries
                appVersion: packageJson.version // Pass app version
            });
        }

        // Read the log file
        fs.readFile(userLogPath, 'utf8', (err, data) => {
            if (err) {
                console.error(`Error reading activity log for user ${username}:`, err);
                return res.status(500).send('Error reading activity log.');
            }

            // Convert log entries to HTML format
            const logEntries = data.split('\n').filter(entry => entry.trim() !== '');
            // const formattedLog = logEntries.map(entry => `<div class="log-entry">${entry}</div>`).join(''); // Not needed directly

            // Parse log entries to extract timestamps and actions
            const parsedEntries = logEntries.map(entry => {
                // Extract timestamp from ISO format at the beginning of the line
                const timestampMatch = entry.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)/);
                const timestamp = timestampMatch ? new Date(timestampMatch[1]) : new Date();

                // Extract IP address
                const ipMatch = entry.match(/\[([\d\.:]+|unknown)\]/); // Updated regex for IPv6
                const ip = ipMatch ? ipMatch[1] : 'unknown';

                // Extract username
                const usernameMatch = entry.match(/\[([\w\.-]+)\]/); // Allow dots and hyphens in username
                const logUsername = usernameMatch ? usernameMatch[1] : 'system';

                // Extract action (everything after the last dash)
                const actionMatch = entry.match(/- (.+)$/);
                const action = actionMatch ? actionMatch[1] : entry;

                return {
                    timestamp,
                    formattedTime: timestamp.toLocaleString(),
                    ip,
                    username: logUsername,
                    action,
                    rawEntry: entry
                };
            });

            // Sort entries by timestamp (newest first)
            parsedEntries.sort((a, b) => b.timestamp - a.timestamp);

            // Apply pagination
            const paginatedData = paginateArray(parsedEntries, page, itemsPerPage);

            // Render the activity log template
            res.render('activity-log', {
                username: username,
                userIp: req.ip || req.connection?.remoteAddress || 'unknown', // Pass user IP
                entries: paginatedData.items,
                pagination: paginatedData.pagination,
                appVersion: packageJson.version // Pass app version
            });

            // Log this activity
            logActivity(req, `Viewed activity log`);
        });
    } catch (err) {
        console.error(`Error in GET /activity-log handler for user ${username}:`, err);
        res.status(500).send('Error processing activity log request.');
    }
});

// Route to view all publicly shared files
app.get('/shared-public', (req, res) => { // ensureAuthenticated applied via app.use
    const page = parseInt(req.query.page) || 1; // Current page, default to 1
    const itemsPerPage = 10; // Number of items per page

    try {
        // Get all users
        const usernames = Object.keys(users);
        const allPublicFiles = [];

        // For each user, check their public directory
        usernames.forEach(username => {
            try {
                const publicDir = path.join(userFilesBaseDir, username, 'public');

                // Skip if public directory doesn't exist
                if (!fs.existsSync(publicDir)) {
                    return;
                }

                // Function to recursively get all files in a directory
                const getFilesRecursively = (dir, basePath = '') => {
                    const entries = fs.readdirSync(dir, { withFileTypes: true });

                    entries.forEach(entry => {
                        const fullPath = path.join(dir, entry.name);
                        const relativePath = path.join(basePath, entry.name).replace(/\\/g, '/'); // Ensure forward slashes

                        if (entry.isDirectory()) {
                            // Recursively process subdirectories
                            getFilesRecursively(fullPath, relativePath);
                        } else {
                            // Add file to the list
                            const stats = fs.statSync(fullPath);
                            allPublicFiles.push({
                                name: entry.name,
                                path: relativePath,
                                owner: username,
                                mtime: stats.mtime,
                                size: stats.size
                            });
                        }
                    });
                };

                // Get all files in the user's public directory
                getFilesRecursively(publicDir);

            } catch (err) {
                console.error(`Error reading public directory for user ${username}:`, err);
                // Continue with next user
            }
        });

        // Filter out files owned by the current user
        const filteredPublicFiles = allPublicFiles.filter(file => file.owner !== req.session.user.username);

        // Sort files by modification time (newest first)
        filteredPublicFiles.sort((a, b) => b.mtime - a.mtime);

        // Apply pagination
        const paginatedData = paginateArray(filteredPublicFiles, page, itemsPerPage);

        // Function to format file size in a human-readable format
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // Render the shared files template
        res.render('shared-public', {
            username: req.session.user.username,
            userIp: req.ip || req.connection?.remoteAddress || 'unknown', // Pass user IP
            files: paginatedData.items, // Use the paginated list
            pagination: paginatedData.pagination,
            formatFileSize: formatFileSize, // Pass the format function to the view
            appVersion: packageJson.version // Pass app version
        });

        // Log this activity
        logActivity(req, `Viewed shared public files`);

    } catch (err) {
        console.error('Error in GET /shared-public handler:', err);
        res.status(500).send('Error retrieving shared files.');
    }
});

// --- Settings Routes ---

// GET /settings - Display settings page
app.get('/settings', (req, res) => { // ensureAuthenticated applied via app.use
    const username = req.session.user.username;
    const userData = users[username] || {}; // Get user data, default to empty if somehow missing

    res.render('settings', {
        username: username,
        userIp: req.ip || req.connection?.remoteAddress || 'unknown',
        name: userData.name || '', // Pass current name
        location: userData.location || '', // Pass current location
        message: req.query.message, // For success messages after redirect
        error: req.query.error, // For error messages after redirect
        appVersion: packageJson.version // Pass app version
    });
});

// POST /update-profile - Handle profile information updates
app.post('/update-profile', (req, res) => { // ensureAuthenticated applied via app.use
    const username = req.session.user.username;
    const { name, location } = req.body;

    if (users[username]) {
        users[username].name = name || ''; // Update name (allow empty)
        users[username].location = location || ''; // Update location (allow empty)
        saveUsers();
        logActivity(req, `Updated profile information for user: ${username}`);
        res.redirect('/settings?message=Profile updated successfully.');
    } else {
        // Should not happen if user is logged in, but handle defensively
        res.redirect('/settings?error=User not found.');
    }
});

// POST /change-password - Handle password change requests
app.post('/change-password', async (req, res) => { // ensureAuthenticated applied via app.use
    const username = req.session.user.username;
    const { currentPassword, newPassword, confirmNewPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmNewPassword) {
        return res.redirect('/settings?error=All password fields are required.');
    }
    if (newPassword !== confirmNewPassword) {
        return res.redirect('/settings?error=New passwords do not match.');
    }
    if (newPassword.length < 6) { // Basic length check (add more complex rules if needed)
         return res.redirect('/settings?error=New password must be at least 6 characters long.');
    }


    const user = users[username];
    if (!user) {
        // Should not happen
        return res.redirect('/settings?error=User not found.');
    }

    try {
        // Verify current password
        const correctPassword = await argon2.verify(user.hash, currentPassword);
        if (!correctPassword) {
            return res.redirect('/settings?error=Incorrect current password.');
        }

        // Hash the new password
        const newPasswordHash = await argon2.hash(newPassword, {
             type: argon2.argon2id,
             salt: crypto.randomBytes(16)
         });

        // Update user's hash
        users[username].hash = newPasswordHash;
        saveUsers();

        logActivity(req, `Changed password for user: ${username}`);
        res.redirect('/settings?message=Password changed successfully.');

    } catch (err) {
        console.error(`Error changing password for user ${username}:`, err);
        res.redirect('/settings?error=An error occurred while changing password.');
    }
});

// --- End Settings Routes ---


// Start the server
app.listen(port, '0.0.0.0', () => {
    console.log(`File share server listening at http://0.0.0.0:${port}`);
});