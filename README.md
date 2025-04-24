# Simple Node.js File Sharing Application

A web-based file sharing application built with Node.js, Express, and EJS templating. Allows users to manage their private files, share files publicly, and view activity logs.

## Features

*   **User Authentication:** Secure signup and login using Argon2 password hashing.
*   **File Management:**
    *   Upload files to private directories.
    *   Download private files.
    *   Create folders within private directories.
    *   Delete files and folders (including recursive deletion for folders).
*   **Public Sharing:**
    *   Share individual files publicly.
    *   Unshare (make private) previously shared files.
    *   View a list of all publicly shared files (excluding your own).
*   **Activity Logging:**
    *   Logs user actions (login, logout, signup, upload, download, delete, share, unshare, folder creation, log viewing) with timestamp, IP address, and username.
    *   Main activity log (`activity.log`).
    *   User-specific logs (`user_logs/<username>.log`).
    *   View your own activity log within the application with pagination and search.
*   **User Settings:**
    *   Dedicated settings page (`/settings`).
    *   Update optional profile information (Name, Location).
    *   Change account password (requires current password verification).
*   **UI:**
    *   Sidebar navigation.
    *   Material Icons integration.
    *   Custom CSS theme (greyish-blue primary color).
    *   Responsive design for different screen sizes.
    *   Pagination for file lists and activity logs.

## Tech Stack

*   **Backend:** Node.js, Express.js
*   **Templating:** EJS (Embedded JavaScript templates)
*   **Authentication:** `express-session` for session management, `argon2` for password hashing.
*   **File Uploads:** `multer`
*   **Frontend:** HTML, CSS, Vanilla JavaScript, Material Icons

## Setup & Installation

1.  **Prerequisites:** Ensure you have Node.js and npm installed.
2.  **Clone/Download:** Get the project files onto your local machine.
3.  **Install Dependencies:** Open a terminal in the project root directory (`c:/Local-File-Share`) and run:
    ```bash
    npm install
    ```
    This will install Express, EJS, Multer, Argon2, session management, and other necessary packages listed in `package.json`.

## Running the Application

1.  **Start the Server:** From the project root directory, run:
    ```bash
    node server.js
    ```
2.  **Access:** Open your web browser and navigate to `http://localhost:8080` (or the configured port if changed in `server.js`).

## File Structure

*   `server.js`: The main application file containing the Express server setup, routes, and logic.
*   `views/`: Contains EJS template files for different pages (`index.ejs`, `login.ejs`, `signup.ejs`, `activity-log.ejs`, `shared-public.ejs`, `settings.ejs`).
*   `public/`: Contains static assets served directly to the client (CSS, client-side JavaScript).
    *   `style.css`: Main stylesheet for the application.
    *   `script.js`: Client-side JavaScript (currently minimal, handles form visibility).
*   `user_files/`: Base directory where user files are stored.
    *   `<username>/`: Each user gets their own directory.
        *   `private/`: User's private files and folders.
        *   `public/`: Copies of files the user has explicitly shared.
*   `user_logs/`: Contains individual activity logs for each user (`<username>.log`).
*   `users.json`: Stores user credentials (username, hashed password, name, location). **Note:** In a production environment, use a proper database instead.
*   `activity.log`: Main log file recording all significant server activities.
*   `package.json` / `package-lock.json`: Node.js project configuration and dependency lock file.
*   `node_modules/`: Directory where npm dependencies are installed (created after `npm install`).