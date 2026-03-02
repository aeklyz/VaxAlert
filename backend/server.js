require("dotenv").config();
const path = require("path");
const crypto = require("crypto");
const https = require("https");
const { db, auth } = require("./config/firebase");
const nodemailer = require("nodemailer");
const express = require("express");
const cors = require("cors");

const app = express();

// Call Firebase Auth REST API (works in all Node versions, no global fetch needed)
function firebaseSignInWithPassword(apiKey, email, password) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      email: email.trim(),
      password,
      returnSecureToken: true,
    });
    const url = new URL(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`);
    const req = https.request(
      {
        hostname: url.hostname,
        path: url.pathname + url.search,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => { data += chunk; });
        res.on("end", () => {
          try {
            const parsed = JSON.parse(data);
            if (res.statusCode >= 200 && res.statusCode < 300) resolve(parsed);
            else reject({ statusCode: res.statusCode, ...parsed });
          } catch (e) {
            reject(new Error(data || "Invalid response"));
          }
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

const VERIFICATION_TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours
const emailTransporter = process.env.EMAIL_USER && process.env.EMAIL_PASS
  ? nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE || "gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    })
  : null;

// Middleware
app.use(cors());
app.use(express.json());

// Handle invalid JSON bodies
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    return res.status(400).json({ error: "Invalid JSON in request body." });
  }
  return next(err);
});

// Serve frontend so register/login etc. are same-origin
app.use(express.static(path.join(__dirname, "..", "frontend")));

// Default route - redirect to login
app.get("/", (req, res) => {
  res.redirect("/login.html");
});

// Test route
app.get("/api", (req, res) => {
  res.send("VaxAlert API running...");
});

// Test Firestore connection
app.get("/test-firestore", async (req, res) => {
  try {
    const snapshot = await db.collection("test").get();
    res.json({ message: "Connected to Firestore!", count: snapshot.size });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Helpful message when someone opens the endpoint in the browser (GET)
app.get("/api/auth/register", (req, res) => {
  return res.status(405).json({
    error: "Method Not Allowed. Use POST /api/auth/register with a JSON body.",
  });
});

// Password validation (at least 8 characters, one number, one symbol)
function isPasswordValid(password) {
  if (!password || password.length < 8) return false;
  if (!/\d/.test(password)) return false;
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) return false;
  return true;
}

// ─── MIDDLEWARE: Verify Firebase ID Token ────────────────────────────────────
function verifyIdToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or invalid authorization header." });
  }

  const idToken = authHeader.substring(7);
  auth
    .verifyIdToken(idToken)
    .then((decodedToken) => {
      req.uid = decodedToken.uid;
      next();
    })
    .catch((error) => {
      console.error("Token verification error:", error.message);
      res.status(401).json({ error: "Invalid or expired token." });
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Register route
app.post("/api/auth/register", async (req, res) => {
  const { email, password, firstName, lastName, contactNumber } = req.body;

  if (!email || !password || !firstName || !lastName || !contactNumber) {
    return res.status(400).json({ error: "All fields are required." });
  }

  if (!isPasswordValid(password)) {
    return res.status(400).json({
      error: "Password must be at least 8 characters and include one number and one symbol.",
    });
  }

  try {
    // Check if email already exists
    try {
      await auth.getUserByEmail(email);
      return res.status(400).json({ error: "This email is already registered." });
    } catch (e) {
      if (e.code !== "auth/user-not-found") throw e;
    }

    // Check if contact number already exists
    const existingContact = await db.collection("users").where("contactNumber", "==", contactNumber.trim()).limit(1).get();
    if (!existingContact.empty) {
      return res.status(400).json({ error: "This contact number is already registered." });
    }

    // Create user in Firebase Auth
    const userRecord = await auth.createUser({
      email: email.trim(),
      password,
      displayName: `${firstName.trim()} ${lastName.trim()}`,
    });

    const trimmedEmail = email.trim();

    // Save user details in Firestore
    await db.collection("users").doc(userRecord.uid).set({
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: trimmedEmail,
      contactNumber: contactNumber.trim(),
      role: "parent",
      emailVerified: false,
      createdAt: Date.now(),
    });

    // Create default preferences for the user
    await db.collection("preferences").doc(userRecord.uid).set({
      reminderMethod: "both", // "sms", "email", or "both"
      reminderDaysBefore: 7,
      updatedAt: Date.now(),
    });

    // Create verification token and send email
    const token = crypto.randomBytes(32).toString("hex");
    const baseUrl = process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 5000}`;
    const verifyUrl = `${baseUrl}/api/auth/verify-email?token=${token}`;

    await db.collection("emailVerificationTokens").doc(token).set({
      userId: userRecord.uid,
      email: trimmedEmail,
      createdAt: Date.now(),
    });

    if (emailTransporter) {
      try {
        await emailTransporter.sendMail({
          from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
          to: trimmedEmail,
          subject: "Verify your VaxAlert email",
          html: `
            <p>Hi ${firstName.trim()},</p>
            <p>Please verify your email by clicking the link below:</p>
            <p><a href="${verifyUrl}">Verify my email</a></p>
            <p>This link expires in 24 hours.</p>
            <p>If you didn't create an account, you can ignore this email.</p>
            <p>— VaxAlert</p>
          `,
        });
      } catch (err) {
        console.error("Verification email failed:", err.message);
      }
    } else {
      console.warn("Email not configured. Verification link:", verifyUrl);
    }

    res.status(201).json({
      message: "User registered successfully. Please verify your email.",
      userId: userRecord.uid,
      ...(emailTransporter ? {} : { verificationLink: verifyUrl }),
    });
  } catch (error) {
    console.error("Register error:", error.code || error.message, error);
    let message = "Registration failed.";
    if (error.code === "auth/email-already-exists") {
      message = "This email is already registered.";
    } else if (error.message && typeof error.message === "string") {
      message = error.message;
    }
    message = String(message || "Registration failed.");
    const status = (error.code && String(error.code).startsWith("auth/")) ? 400 : 500;
    if (!res.headersSent) {
      res.status(status).json({ error: message });
    }
  }
});

// Verify email route
app.get("/api/auth/verify-email", async (req, res) => {
  const { token } = req.query;
  const baseUrl = process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 5000}`;
  const loginUrl = process.env.LOGIN_PAGE_URL || `${baseUrl}/login.html`;

  if (!token) {
    return res.redirect(`${loginUrl}?error=missing-token`);
  }

  try {
    const tokenRef = db.collection("emailVerificationTokens").doc(token);
    const tokenSnap = await tokenRef.get();

    if (!tokenSnap.exists) {
      return res.redirect(`${loginUrl}?error=invalid-token`);
    }

    const data = tokenSnap.data();
    if (Date.now() - data.createdAt > VERIFICATION_TOKEN_EXPIRY_MS) {
      await tokenRef.delete();
      return res.redirect(`${loginUrl}?error=token-expired`);
    }

    const { userId } = data;

    await db.collection("users").doc(userId).update({ emailVerified: true });

    try {
      await auth.updateUser(userId, { emailVerified: true });
    } catch (_) {}

    await tokenRef.delete();

    return res.redirect(`${loginUrl}?verified=1`);
  } catch (error) {
    console.error("Verify email error:", error);
    return res.redirect(`${loginUrl}?error=verification-failed`);
  }
});

// Login route
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const apiKey = process.env.FIREBASE_WEB_API_KEY;
  if (!apiKey) {
    return res.status(503).json({ error: "Login is not configured. Set FIREBASE_WEB_API_KEY in .env" });
  }

  try {
    const data = await firebaseSignInWithPassword(apiKey, email, password);
    const uid = data.localId;

    const userDoc = await db.collection("users").doc(uid).get();
    if (!userDoc.exists) {
      return res.status(400).json({ error: "User profile not found." });
    }

    const emailVerified = userDoc.data().emailVerified === true;
    if (!emailVerified) {
      return res.status(403).json({ error: "Please verify your email first. Check your inbox for the verification link." });
    }

    return res.status(200).json({
      message: "Login successful!",
      userId: uid,
      email: data.email,
      idToken: data.idToken,
    });
  } catch (err) {
    const fbMsg = err.error?.message || err.message || "";
    const isInvalidCreds =
      fbMsg.includes("INVALID_LOGIN_CREDENTIALS") ||
      fbMsg.includes("EMAIL_NOT_FOUND") ||
      fbMsg.includes("INVALID_PASSWORD") ||
      err.statusCode === 401;

    if (isInvalidCreds) {
      return res.status(401).json({ error: "Invalid email or password." });
    }
    if (fbMsg.includes("API key")) {
      return res.status(503).json({
        error: "Server auth config error. Check FIREBASE_WEB_API_KEY and API key restrictions in Firebase Console.",
      });
    }

    console.error("Login error:", err);
    return res.status(500).json({
      error: err.error?.message || err.message || "Login failed.",
    });
  }
});

// Change password route
app.put("/api/auth/change-password", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    const { newPassword } = req.body;

    if (!newPassword || !isPasswordValid(newPassword)) {
      return res.status(400).json({
        error: "New password must be at least 8 characters and include one number and one symbol.",
      });
    }

    await auth.updateUser(userId, { password: newPassword });

    res.status(200).json({ message: "Password updated successfully." });
  } catch (error) {
    console.error("Change password error:", error);
    res.status(500).json({ error: "Failed to change password." });
  }
});

// POST /api/auth/sync-verification - Sync Firebase Auth emailVerified to Firestore
// Also creates the Firestore user doc if missing (safety net for legacy registrations)
app.post("/api/auth/sync-verification", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;

    // Get the Firebase Auth user
    const firebaseUser = await auth.getUser(userId);

    // Check if Firestore user doc exists
    const userDoc = await db.collection("users").doc(userId).get();

    if (!userDoc.exists) {
      // Create the missing Firestore user document from Firebase Auth data
      console.log(`Creating missing Firestore doc for user ${userId}`);
      const displayParts = (firebaseUser.displayName || "").split(" ");
      await db.collection("users").doc(userId).set({
        firstName: displayParts[0] || "",
        lastName: displayParts.slice(1).join(" ") || "",
        email: firebaseUser.email || "",
        contactNumber: "",
        role: "parent",
        emailVerified: firebaseUser.emailVerified || false,
        createdAt: Date.now(),
      });

      // Also create default preferences
      await db.collection("preferences").doc(userId).set({
        reminderMethod: "both",
        reminderDaysBefore: 7,
        updatedAt: Date.now(),
      });
    } else if (firebaseUser.emailVerified) {
      // Update Firestore to match Firebase Auth
      await db.collection("users").doc(userId).update({ emailVerified: true });
    }

    return res.status(200).json({ 
      message: "Verification status synced.", 
      emailVerified: firebaseUser.emailVerified 
    });
  } catch (error) {
    console.error("Sync verification error:", error);
    res.status(500).json({ error: "Failed to sync verification status." });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// PARENT PROFILE ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/parent/profile
app.get("/api/parent/profile", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    console.log(`Fetching profile for user ${userId}`);
    
    const userDoc = await db.collection("users").doc(userId).get();

    if (!userDoc.exists) {
      console.error(`User document ${userId} not found in Firestore`);
      return res.status(404).json({ error: "User profile not found." });
    }

    const userData = userDoc.data();
    const response = {
      id: userDoc.id,
      firstName: userData.firstName || "",
      lastName: userData.lastName || "",
      email: userData.email || "",
      contactNumber: userData.contactNumber || "",
      role: userData.role || "",
    };
    
    console.log(`Successfully fetched profile for user ${userId}:`, response.firstName, response.lastName);
    res.status(200).json(response);
  } catch (error) {
    console.error("Fetch profile error:", error);
    res.status(500).json({ error: "Failed to fetch profile." });
  }
});

// PUT /api/parent/update-profile
app.put("/api/parent/update-profile", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    const { firstName, lastName, contactNumber } = req.body;

    if (!firstName || !lastName || !contactNumber) {
      return res.status(400).json({ error: "First name, last name, and contact number are required." });
    }

    // Check if contact number is used by someone else
    const existingContact = await db
      .collection("users")
      .where("contactNumber", "==", contactNumber.trim())
      .limit(1)
      .get();

    for (const doc of existingContact.docs) {
      if (doc.id !== userId) {
        return res.status(400).json({ error: "This contact number is already in use." });
      }
    }

    await db.collection("users").doc(userId).update({
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      contactNumber: contactNumber.trim(),
      updatedAt: Date.now(),
    });

    try {
      await auth.updateUser(userId, {
        displayName: `${firstName.trim()} ${lastName.trim()}`,
      });
    } catch (_) {}

    res.status(200).json({
      message: "Profile updated successfully.",
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      contactNumber: contactNumber.trim(),
    });
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({ error: "Failed to update profile." });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHILDREN ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/parent/children - Fetch all children linked to the parent
app.get("/api/parent/children", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    console.log(`Fetching children for parent ${userId}`);
    
    // FIX: Removed .orderBy("createdAt", "desc") — requires a Firestore composite
    // index that may not exist. Sort in-memory instead.
    const childrenSnapshot = await db
      .collection("children")
      .where("parentId", "==", userId)
      .get();

    const children = [];
    childrenSnapshot.forEach((doc) => {
      const data = doc.data();
      // Calculate age from birthDate
      let age = null;
      if (data.birthDate) {
        const birth = new Date(typeof data.birthDate === "number" ? data.birthDate : data.birthDate.seconds * 1000);
        const now = new Date();
        age = now.getFullYear() - birth.getFullYear();
        const monthDiff = now.getMonth() - birth.getMonth();
        if (monthDiff < 0 || (monthDiff === 0 && now.getDate() < birth.getDate())) {
          age--;
        }
      }
      children.push({
        id: doc.id,
        firstName: data.firstName,
        lastName: data.lastName,
        birthDate: data.birthDate,
        sex: data.sex,
        age,
        _createdAt: data.createdAt || 0,
      });
    });

    // Sort by createdAt descending (newest first)
    children.sort((a, b) => (b._createdAt || 0) - (a._createdAt || 0));

    // Remove internal sort field before sending response
    const result = children.map(({ _createdAt, ...rest }) => rest);

    console.log(`Found ${result.length} children for parent ${userId}`);
    res.status(200).json(result);
  } catch (error) {
    console.error("Fetch children error:", error);
    res.status(500).json({ error: "Failed to fetch children." });
  }
});

// POST /api/parent/children - Add a new child
app.post("/api/parent/children", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    const { firstName, lastName, birthDate, sex } = req.body;

    if (!firstName || !lastName || !birthDate) {
      return res.status(400).json({ error: "First name, last name, and birth date are required." });
    }

    console.log(`Adding child ${firstName} ${lastName} for parent ${userId}`);

    const childRef = await db.collection("children").add({
      parentId: userId,
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      birthDate: new Date(birthDate).getTime(),
      sex: sex || "not specified",
      createdAt: Date.now(),
    });

    // Auto-generate vaccination schedule based on Philippine EPI schedule
    try {
      await generateVaccinationSchedule(childRef.id, new Date(birthDate));
      console.log(`Successfully created child ${childRef.id} with vaccination schedule`);
    } catch (scheduleError) {
      console.error(`Failed to generate schedule for child ${childRef.id}:`, scheduleError);
      // Delete the child if schedule generation failed
      await db.collection("children").doc(childRef.id).delete();
      return res.status(500).json({ error: "Failed to generate vaccination schedule." });
    }

    res.status(201).json({
      message: "Child added successfully.",
      childId: childRef.id,
    });
  } catch (error) {
    console.error("Add child error:", error);
    res.status(500).json({ error: "Failed to add child." });
  }
});

// PUT /api/parent/children/:childId - Update child info
app.put("/api/parent/children/:childId", verifyIdToken, async (req, res) => {
  try {
    const { childId } = req.params;
    const userId = req.uid;

    const childDoc = await db.collection("children").doc(childId).get();
    if (!childDoc.exists || childDoc.data().parentId !== userId) {
      return res.status(403).json({ error: "Access denied." });
    }

    const { firstName, lastName, birthDate, sex } = req.body;
    const updateData = {};
    if (firstName) updateData.firstName = firstName.trim();
    if (lastName) updateData.lastName = lastName.trim();
    if (birthDate) updateData.birthDate = new Date(birthDate).getTime();
    if (sex) updateData.sex = sex;
    updateData.updatedAt = Date.now();

    await db.collection("children").doc(childId).update(updateData);

    res.status(200).json({ message: "Child updated successfully." });
  } catch (error) {
    console.error("Update child error:", error);
    res.status(500).json({ error: "Failed to update child." });
  }
});

// DELETE /api/parent/children/:childId - Remove a child
app.delete("/api/parent/children/:childId", verifyIdToken, async (req, res) => {
  try {
    const { childId } = req.params;
    const userId = req.uid;

    const childDoc = await db.collection("children").doc(childId).get();
    if (!childDoc.exists || childDoc.data().parentId !== userId) {
      return res.status(403).json({ error: "Access denied." });
    }

    // Delete all vaccinations subcollection
    const vaccBatch = db.batch();
    const vaccSnapshot = await db.collection("children").doc(childId).collection("vaccinations").get();
    vaccSnapshot.forEach((doc) => vaccBatch.delete(doc.ref));
    await vaccBatch.commit();

    // Delete child document
    await db.collection("children").doc(childId).delete();

    res.status(200).json({ message: "Child removed successfully." });
  } catch (error) {
    console.error("Delete child error:", error);
    res.status(500).json({ error: "Failed to remove child." });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// STAFF ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/staff/profile
app.get("/api/staff/profile", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    console.log(`Fetching staff profile for user ${userId}`);
    
    const userDoc = await db.collection("users").doc(userId).get();

    if (!userDoc.exists) {
      console.error(`Staff user document ${userId} not found`);
      return res.status(404).json({ error: "Staff profile not found." });
    }

    const userData = userDoc.data();
    
    // Verify this user is staff
    if (userData.role !== "staff") {
      console.warn(`Access denied: User ${userId} is not staff (role: ${userData.role})`);
      return res.status(403).json({ error: "Unauthorized. Staff access only." });
    }

    const response = {
      id: userDoc.id,
      firstName: userData.firstName || "",
      lastName: userData.lastName || "",
      email: userData.email || "",
      contactNumber: userData.contactNumber || "",
      role: userData.role,
    };
    
    console.log(`Successfully fetched staff profile for user ${userId}:`, response.firstName, response.lastName);
    res.status(200).json(response);
  } catch (error) {
    console.error("Fetch staff profile error:", error);
    res.status(500).json({ error: "Failed to fetch staff profile." });
  }
});

// GET /api/staff/children - Fetch all children for staff view
app.get("/api/staff/children", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    console.log(`Fetching all children list for staff ${userId}`);
    
    // Verify staff role
    const staffDoc = await db.collection("users").doc(userId).get();
    if (!staffDoc.exists || staffDoc.data().role !== "staff") {
      return res.status(403).json({ error: "Unauthorized. Staff access only." });
    }

    // Get all children from all parents
    const childrenSnapshot = await db.collection("children").get();

    const children = [];
    for (const childDoc of childrenSnapshot.docs) {
      const childData = childDoc.data();
      const parentId = childData.parentId;
      
      // Get parent info
      const parentDoc = await db.collection("users").doc(parentId).get();
      const parentData = parentDoc.exists ? parentDoc.data() : { firstName: "Unknown", lastName: "Parent" };
      
      // Get vaccination summary
      const vaccSnapshot = await db
        .collection("children")
        .doc(childDoc.id)
        .collection("vaccinations")
        .get();
      
      let overdue = 0, upcoming = 0, completed = 0;
      const now = Date.now();
      
      vaccSnapshot.forEach((vaccDoc) => {
        const vdata = vaccDoc.data();
        const dueTime = typeof vdata.dueDate === "number" ? vdata.dueDate : vdata.dueDate?.seconds * 1000;
        const daysUntilDue = Math.floor((dueTime - now) / (1000 * 60 * 60 * 24));
        
        if (vdata.type === "administered") completed++;
        else if (daysUntilDue < 0) overdue++;
        else upcoming++;
      });

      // Calculate age
      let age = null;
      if (childData.birthDate) {
        const birth = new Date(typeof childData.birthDate === "number" ? childData.birthDate : childData.birthDate.seconds * 1000);
        const now_date = new Date();
        age = now_date.getFullYear() - birth.getFullYear();
        const monthDiff = now_date.getMonth() - birth.getMonth();
        if (monthDiff < 0 || (monthDiff === 0 && now_date.getDate() < birth.getDate())) {
          age--;
        }
      }

      children.push({
        id: childDoc.id,
        firstName: childData.firstName,
        lastName: childData.lastName,
        dob: childData.birthDate,
        age,
        parentName: `${parentData.firstName} ${parentData.lastName}`,
        parentEmail: parentData.email,
        overdue,
        upcoming,
        completed,
      });
    }

    console.log(`Found ${children.length} total children for staff view`);
    res.status(200).json(children);
  } catch (error) {
    console.error("Fetch children error:", error);
    res.status(500).json({ error: "Failed to fetch children." });
  }
});

// GET /api/staff/vaccinations - Fetch all vaccinations for staff dashboard
app.get("/api/staff/vaccinations", verifyIdToken, async (req, res) => {
  const { status } = req.query; // "due", "overdue", or "upcoming"
  
  try {
    const userId = req.uid;
    
    // Verify staff role
    const staffDoc = await db.collection("users").doc(userId).get();
    if (!staffDoc.exists || staffDoc.data().role !== "staff") {
      return res.status(403).json({ error: "Unauthorized. Staff access only." });
    }

    const vaccinations = [];
    const now = Date.now();
    
    const childrenSnapshot = await db.collection("children").get();
    
    for (const childDoc of childrenSnapshot.docs) {
      const childData = childDoc.data();
      
      const vaccSnapshot = await db
        .collection("children")
        .doc(childDoc.id)
        .collection("vaccinations")
        .get();
      
      vaccSnapshot.forEach((vaccDoc) => {
        const vdata = vaccDoc.data();
        
        // Skip administered vaccines
        if (vdata.type === "administered") return;
        
        const dueTime = typeof vdata.dueDate === "number" ? vdata.dueDate : vdata.dueDate?.seconds * 1000;
        const daysUntilDue = Math.floor((dueTime - now) / (1000 * 60 * 60 * 24));
        
        let vStatus = "upcoming";
        if (daysUntilDue < 0) vStatus = "overdue";
        else if (daysUntilDue <= 30) vStatus = "due";
        
        // Filter by status if provided
        if (status && vStatus !== status) return;
        
        vaccinations.push({
          id: vaccDoc.id,
          childId: childDoc.id,
          childName: `${childData.firstName} ${childData.lastName}`,
          vaccineName: vdata.vaccineName,
          dose: vdata.dose,
          dueDate: dueTime,
          status: vStatus,
        });
      });
    }

    console.log(`Found ${vaccinations.length} vaccinations with status: ${status || "all"}`);
    res.status(200).json(vaccinations);
  } catch (error) {
    console.error("Fetch vaccinations error:", error);
    res.status(500).json({ error: "Failed to fetch vaccinations." });
  }
});

// GET /api/staff/reminder-logs - Fetch all reminder logs for staff view
app.get("/api/staff/reminder-logs", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    
    // Verify staff role
    const userDoc = await db.collection("users").doc(userId).get();
    if (!userDoc.exists || userDoc.data().role !== "staff") {
      return res.status(403).json({ error: "Access denied. Staff role required." });
    }
    
    const reminderLogs = [];
    
    // Get all reminder logs from all parents/children
    const logsSnap = await db.collection("reminderLogs").get();
    logsSnap.forEach((doc) => {
      const data = doc.data();
      reminderLogs.push({
        id: doc.id,
        sentAt: data.sentAt,
        childName: data.childName,
        method: data.method,
        status: data.status,
      });
    });
    
    // Sort by date (newest first)
    reminderLogs.sort((a, b) => (b.sentAt || 0) - (a.sentAt || 0));
    console.log(`Staff reminder logs retrieved: ${reminderLogs.length} logs`);
    res.json(reminderLogs);
  } catch (error) {
    console.error("Staff reminder logs error:", error);
    res.status(500).json({ error: "Failed to fetch reminder logs." });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VACCINATION SCHEDULE & HISTORY ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// Philippine EPI Vaccination Schedule (age in days from birth)
const PH_EPI_SCHEDULE = [
  { vaccine: "BCG", dose: "Dose 1", daysFromBirth: 0 },
  { vaccine: "Hepatitis B", dose: "Dose 1", daysFromBirth: 0 },
  { vaccine: "Pentavalent Vaccine (DPT-HepB-Hib)", dose: "Dose 1", daysFromBirth: 42 },
  { vaccine: "Oral Polio Vaccine (OPV)", dose: "Dose 1", daysFromBirth: 42 },
  { vaccine: "Pneumococcal Conjugate Vaccine (PCV)", dose: "Dose 1", daysFromBirth: 42 },
  { vaccine: "Pentavalent Vaccine (DPT-HepB-Hib)", dose: "Dose 2", daysFromBirth: 70 },
  { vaccine: "Oral Polio Vaccine (OPV)", dose: "Dose 2", daysFromBirth: 70 },
  { vaccine: "Pneumococcal Conjugate Vaccine (PCV)", dose: "Dose 2", daysFromBirth: 70 },
  { vaccine: "Pentavalent Vaccine (DPT-HepB-Hib)", dose: "Dose 3", daysFromBirth: 98 },
  { vaccine: "Oral Polio Vaccine (OPV)", dose: "Dose 3", daysFromBirth: 98 },
  { vaccine: "Pneumococcal Conjugate Vaccine (PCV)", dose: "Dose 3", daysFromBirth: 98 },
  { vaccine: "Inactivated Polio Vaccine (IPV)", dose: "Dose 1", daysFromBirth: 98 },
  { vaccine: "MMR", dose: "Dose 1", daysFromBirth: 270 },
  { vaccine: "Japanese Encephalitis", dose: "Dose 1", daysFromBirth: 270 },
  { vaccine: "MMR", dose: "Dose 2", daysFromBirth: 365 },
  { vaccine: "Japanese Encephalitis", dose: "Dose 2", daysFromBirth: 365 },
];

// Generate vaccination schedule for a child based on birth date
async function generateVaccinationSchedule(childId, birthDate) {
  const batch = db.batch();

  for (const item of PH_EPI_SCHEDULE) {
    const dueDate = new Date(birthDate.getTime() + item.daysFromBirth * 24 * 60 * 60 * 1000);
    const vaccRef = db.collection("children").doc(childId).collection("vaccinations").doc();

    batch.set(vaccRef, {
      vaccineName: item.vaccine,
      dose: item.dose,
      dueDate: dueDate.getTime(),
      type: "scheduled", // "scheduled" or "administered"
      administeredDate: null,
      administeredBy: null,
      notes: null,
      createdAt: Date.now(),
    });
  }

  try {
    await batch.commit();
    console.log(`Successfully generated vaccination schedule for child ${childId}`);
  } catch (error) {
    console.error(`Failed to generate vaccination schedule for child ${childId}:`, error);
    throw error;
  }
}

// GET /api/child/:childId/schedule - Fetch vaccination schedule
app.get("/api/child/:childId/schedule", verifyIdToken, async (req, res) => {
  try {
    const { childId } = req.params;
    const userId = req.uid;

    console.log(`Fetching schedule for child ${childId} from parent ${userId}`);

    const childDoc = await db.collection("children").doc(childId).get();
    if (!childDoc.exists) {
      console.warn(`Child document ${childId} not found`);
      return res.status(404).json({ error: "Child not found." });
    }
    
    if (childDoc.data().parentId !== userId) {
      console.warn(`Access denied: Child ${childId} does not belong to user ${userId}`);
      return res.status(403).json({ error: "Access denied." });
    }

    // Fetch ALL vaccinations first, then filter in-memory to avoid composite index requirement
    const allVaccSnapshot = await db
      .collection("children")
      .doc(childId)
      .collection("vaccinations")
      .get();

    const schedule = [];
    const now = Date.now();
    
    allVaccSnapshot.forEach((doc) => {
      const data = doc.data();
      
      // Skip administered vaccinations - they go in history
      if (data.type === "administered") return;
      
      const dueTimestamp = typeof data.dueDate === "number" ? data.dueDate : data.dueDate?.seconds * 1000;
      const daysUntilDue = Math.floor((dueTimestamp - now) / (1000 * 60 * 60 * 24));

      let status = "upcoming";
      if (daysUntilDue < 0) status = "overdue";
      else if (daysUntilDue <= 30) status = "due-soon";

      schedule.push({
        id: doc.id,
        vaccineName: data.vaccineName,
        dose: data.dose,
        dueDate: dueTimestamp,
        status,
        daysUntilDue,
      });
    });

    // Sort by due date
    schedule.sort((a, b) => a.dueDate - b.dueDate);
    
    console.log(`Found ${schedule.length} scheduled vaccinations for child ${childId}`);
    res.status(200).json(schedule);
  } catch (error) {
    console.error("Fetch vaccination schedule error:", error);
    res.status(500).json({ error: "Failed to fetch vaccination schedule." });
  }
});

// GET /api/child/:childId/history - Fetch vaccination history
app.get("/api/child/:childId/history", verifyIdToken, async (req, res) => {
  try {
    const { childId } = req.params;
    const userId = req.uid;

    console.log(`Fetching history for child ${childId} from parent ${userId}`);

    const childDoc = await db.collection("children").doc(childId).get();
    if (!childDoc.exists) {
      console.warn(`Child document ${childId} not found`);
      return res.status(404).json({ error: "Child not found." });
    }
    
    if (childDoc.data().parentId !== userId) {
      console.warn(`Access denied: Child ${childId} does not belong to user ${userId}`);
      return res.status(403).json({ error: "Access denied." });
    }

    // Fetch ALL vaccinations first, then filter in-memory to avoid composite index requirement
    const allVaccSnapshot = await db
      .collection("children")
      .doc(childId)
      .collection("vaccinations")
      .get();

    const history = [];
    
    allVaccSnapshot.forEach((doc) => {
      const data = doc.data();
      
      // Only include administered vaccinations
      if (data.type !== "administered") return;
      
      history.push({
        id: doc.id,
        vaccineName: data.vaccineName,
        dose: data.dose,
        administeredDate: data.administeredDate,
        administeredBy: data.administeredBy,
        notes: data.notes,
      });
    });

    // Sort by administered date (newest first)
    history.sort((a, b) => (b.administeredDate || 0) - (a.administeredDate || 0));
    
    console.log(`Found ${history.length} vaccination records for child ${childId}`);
    res.status(200).json(history);
  } catch (error) {
    console.error("Fetch vaccination history error:", error);
    res.status(500).json({ error: "Failed to fetch vaccination history." });
  }
});

// PUT /api/child/:childId/vaccination/:vaccId/administer - Mark a vaccine as administered
app.put("/api/child/:childId/vaccination/:vaccId/administer", verifyIdToken, async (req, res) => {
  try {
    const { childId, vaccId } = req.params;
    const userId = req.uid;

    // Check if user is parent of child or is staff
    const childDoc = await db.collection("children").doc(childId).get();
    if (!childDoc.exists) {
      return res.status(404).json({ error: "Child not found." });
    }
    
    const userDoc = await db.collection("users").doc(userId).get();
    const userRole = userDoc.data()?.role;
    const isParent = childDoc.data().parentId === userId;
    const isStaff = userRole === "staff";
    
    if (!isParent && !isStaff) {
      return res.status(403).json({ error: "Access denied." });
    }

    const { administeredDate, administeredBy, notes } = req.body;

    await db.collection("children").doc(childId).collection("vaccinations").doc(vaccId).update({
      type: "administered",
      status: "completed",
      administeredDate: administeredDate ? new Date(administeredDate).getTime() : Date.now(),
      administeredBy: administeredBy || "Not specified",
      notes: notes || null,
      updatedAt: Date.now(),
    });

    res.status(200).json({ message: "Vaccination marked as administered." });
  } catch (error) {
    console.error("Administer vaccination error:", error);
    res.status(500).json({ error: "Failed to update vaccination record." });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/admin/profile - Admin profile with role verification
app.get("/api/admin/profile", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    const userDoc = await db.collection("users").doc(userId).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found." });
    }
    
    const userData = userDoc.data();
    if (userData.role !== "admin") {
      return res.status(403).json({ error: "Access denied. Admin role required." });
    }
    
    console.log("Admin profile loaded for:", userData.firstName, userData.lastName);
    res.json({
      uid: userId,
      firstName: userData.firstName,
      lastName: userData.lastName,
      email: userData.email,
      contactNumber: userData.contactNumber,
      role: userData.role,
      createdAt: userData.createdAt,
    });
  } catch (error) {
    console.error("Admin profile error:", error);
    res.status(500).json({ error: "Failed to load admin profile." });
  }
});

// GET /api/admin/vaccinations - All vaccinations for admin dashboard
app.get("/api/admin/vaccinations", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    
    // Verify admin role
    const userDoc = await db.collection("users").doc(userId).get();
    if (!userDoc.exists || userDoc.data().role !== "admin") {
      return res.status(403).json({ error: "Access denied. Admin role required." });
    }
    
    const status = req.query.status; // Optional filter
    const vaccinations = [];
    
    // Get all children from all parents
    const childrenSnap = await db.collection("children").get();
    
    for (const childDoc of childrenSnap.docs) {
      const childData = childDoc.data();
      
      // Get all vaccinations for this child - MUST await
      const vaccsSnap = await childDoc.ref.collection("vaccinations").get();
      
      for (const vaccDoc of vaccsSnap.docs) {
        const vdata = vaccDoc.data();
        if (vdata.type !== "scheduled") continue; // Only scheduled vaccines
        
        const dueTime = vdata.dueDate;
        const daysUntilDue = Math.floor((dueTime - Date.now()) / (1000 * 60 * 60 * 24));
        
        let vStatus = "upcoming";
        if (daysUntilDue < 0) vStatus = "overdue";
        else if (daysUntilDue <= 30) vStatus = "due";
        
        if (status && vStatus !== status) continue;
        
        vaccinations.push({
          id: vaccDoc.id,
          childId: childDoc.id,
          childName: `${childData.firstName} ${childData.lastName}`,
          vaccineName: vdata.vaccineName,
          dose: vdata.dose,
          dueDate: dueTime,
          status: vStatus,
        });
      }
    }
    
    vaccinations.sort((a, b) => a.dueDate - b.dueDate);
    res.json(vaccinations);
  } catch (error) {
    console.error("Admin vaccinations error:", error);
    res.status(500).json({ error: "Failed to load vaccinations." });
  }
});

// GET /api/admin/reminder-logs - All reminder logs for admin
app.get("/api/admin/reminder-logs", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    
    // Verify admin role
    const userDoc = await db.collection("users").doc(userId).get();
    if (!userDoc.exists || userDoc.data().role !== "admin") {
      return res.status(403).json({ error: "Access denied. Admin role required." });
    }
    
    const reminderLogs = [];
    
    // Get all reminder logs from all users
    const logsSnap = await db.collection("reminderLogs").get();
    logsSnap.forEach((doc) => {
      const data = doc.data();
      reminderLogs.push({
        id: doc.id,
        sentAt: data.sentAt,
        childName: data.childName,
        method: data.method,
        status: data.status,
      });
    });
    
    reminderLogs.sort((a, b) => (b.sentAt || 0) - (a.sentAt || 0));
    res.json(reminderLogs);
  } catch (error) {
    console.error("Admin reminder logs error:", error);
    res.status(500).json({ error: "Failed to load reminder logs." });
  }
});

// GET /api/admin/stats - Overall clinic statistics
app.get("/api/admin/stats", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    
    // Verify admin role
    const userDoc = await db.collection("users").doc(userId).get();
    if (!userDoc.exists || userDoc.data().role !== "admin") {
      return res.status(403).json({ error: "Access denied. Admin role required." });
    }
    
    let due = 0, overdue = 0, completed = 0;
    let totalChildren = 0;
    
    // Get all children
    const childrenSnap = await db.collection("children").get();
    totalChildren = childrenSnap.size;
    
    // Count vaccinations by status - MUST await subcollections
    for (const childDoc of childrenSnap.docs) {
      const vaccsSnap = await childDoc.ref.collection("vaccinations").get();
      
      for (const vaccDoc of vaccsSnap.docs) {
        const vdata = vaccDoc.data();
        
        if (vdata.type === "administered") {
          completed++;
        } else if (vdata.type === "scheduled") {
          const dueTime = vdata.dueDate;
          const daysUntilDue = Math.floor((dueTime - Date.now()) / (1000 * 60 * 60 * 24));
          
          if (daysUntilDue < 0) overdue++;
          else if (daysUntilDue <= 30) due++;
        }
      }
    }
    
    res.json({ due, overdue, completed, totalChildren });
  } catch (error) {
    console.error("Admin stats error:", error);
    res.status(500).json({ error: "Failed to load statistics." });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// PREFERENCES ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/parent/preferences
app.get("/api/parent/preferences", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    const prefDoc = await db.collection("preferences").doc(userId).get();

    if (!prefDoc.exists) {
      // Return defaults
      return res.status(200).json({
        reminderMethod: "both",
        reminderDaysBefore: 7,
      });
    }

    res.status(200).json(prefDoc.data());
  } catch (error) {
    console.error("Fetch preferences error:", error);
    res.status(500).json({ error: "Failed to fetch preferences." });
  }
});

// PUT /api/parent/preferences
app.put("/api/parent/preferences", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;
    const { reminderMethod, reminderDaysBefore } = req.body;

    const validMethods = ["sms", "email", "both"];
    if (reminderMethod && !validMethods.includes(reminderMethod)) {
      return res.status(400).json({ error: "Invalid reminder method. Use 'sms', 'email', or 'both'." });
    }

    const updateData = { updatedAt: Date.now() };
    if (reminderMethod) updateData.reminderMethod = reminderMethod;
    if (reminderDaysBefore !== undefined) updateData.reminderDaysBefore = Number(reminderDaysBefore);

    await db.collection("preferences").doc(userId).set(updateData, { merge: true });

    res.status(200).json({ message: "Preferences updated successfully.", ...updateData });
  } catch (error) {
    console.error("Update preferences error:", error);
    res.status(500).json({ error: "Failed to update preferences." });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// REMINDER SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════

// Send reminder email helper
async function sendReminderEmail(toEmail, parentName, childName, vaccineName, dose, dueDate) {
  if (!emailTransporter) {
    console.warn("Email not configured. Skipping reminder email to:", toEmail);
    return { sent: false, reason: "Email not configured" };
  }

  const formattedDate = new Date(dueDate).toLocaleDateString("en-US", {
    year: "numeric", month: "long", day: "numeric",
  });

  try {
    await emailTransporter.sendMail({
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: toEmail,
      subject: `VaxAlert Reminder: ${vaccineName} (${dose}) for ${childName}`,
      html: `
        <div style="font-family: 'Segoe UI', sans-serif; max-width: 500px; margin: 0 auto;">
          <div style="background: #142e5c; color: white; padding: 20px; border-radius: 12px 12px 0 0; text-align: center;">
            <h2 style="margin: 0;">VaxAlert Reminder</h2>
          </div>
          <div style="padding: 24px; background: #f8fafc; border-radius: 0 0 12px 12px;">
            <p>Hi ${parentName},</p>
            <p>This is a reminder that <strong>${childName}</strong> has an upcoming vaccination:</p>
            <div style="background: white; padding: 16px; border-radius: 8px; border-left: 4px solid #f59e0b; margin: 16px 0;">
              <p style="margin: 0;"><strong>${vaccineName}</strong> — ${dose}</p>
              <p style="margin: 4px 0 0; color: #64748b;">Due: ${formattedDate}</p>
            </div>
            <p>Please contact your healthcare provider to schedule the appointment.</p>
            <p style="color: #94a3b8; font-size: 13px;">— VaxAlert Team</p>
          </div>
        </div>
      `,
    });
    return { sent: true, method: "email" };
  } catch (err) {
    console.error("Reminder email failed:", err.message);
    return { sent: false, reason: err.message, method: "email" };
  }
}

// POST /api/reminders/check - Check and send reminders for all parents (cron-like endpoint)
app.post("/api/reminders/check", async (req, res) => {
  // Optional: protect with a secret key for cron jobs
  const cronKey = req.headers["x-cron-key"];
  if (process.env.CRON_SECRET && cronKey !== process.env.CRON_SECRET) {
    return res.status(401).json({ error: "Unauthorized." });
  }

  try {
    const now = Date.now();
    let remindersSent = 0;

    console.log("Starting reminder check at", new Date());

    // Get all parents
    const usersSnapshot = await db.collection("users").where("role", "==", "parent").get();
    console.log(`Found ${usersSnapshot.size} parent accounts`);

    for (const userDoc of usersSnapshot.docs) {
      const userId = userDoc.id;
      const userData = userDoc.data();

      // Get preferences
      const prefDoc = await db.collection("preferences").doc(userId).get();
      const prefs = prefDoc.exists ? prefDoc.data() : { reminderMethod: "both", reminderDaysBefore: 7 };

      // Get all children for this parent
      const childrenSnapshot = await db.collection("children").where("parentId", "==", userId).get();
      console.log(`Parent ${userId} has ${childrenSnapshot.size} children`);

      for (const childDoc of childrenSnapshot.docs) {
        const childData = childDoc.data();
        const childName = `${childData.firstName} ${childData.lastName}`;

        // Get all vaccinations for this child
        const vaccSnapshot = await db
          .collection("children")
          .doc(childDoc.id)
          .collection("vaccinations")
          .get();

        for (const vaccDoc of vaccSnapshot.docs) {
          const vaccData = vaccDoc.data();
          
          // Skip administered vaccinations
          if (vaccData.type === "administered") continue;
          
          const dueDate = typeof vaccData.dueDate === "number" ? vaccData.dueDate : vaccData.dueDate?.seconds * 1000;
          const daysUntilDue = Math.floor((dueDate - now) / (1000 * 60 * 60 * 24));

          // Send reminder if due within the reminder window
          if (daysUntilDue >= 0 && daysUntilDue <= prefs.reminderDaysBefore) {
            // Check if reminder was already sent today
            const today = new Date().toISOString().split("T")[0];
            const existingReminder = await db
              .collection("reminderLogs")
              .where("userId", "==", userId)
              .where("vaccinationId", "==", vaccDoc.id)
              .where("sentDate", "==", today)
              .limit(1)
              .get();

            if (!existingReminder.empty) continue; // Already sent today

            const parentName = `${userData.firstName} ${userData.lastName}`;
            let result = { sent: false };

            // Send email reminder
            if (prefs.reminderMethod === "email" || prefs.reminderMethod === "both") {
              result = await sendReminderEmail(
                userData.email, parentName, childName,
                vaccData.vaccineName, vaccData.dose, dueDate
              );
            }

            // SMS would go here (e.g., Twilio integration)
            if (prefs.reminderMethod === "sms" || prefs.reminderMethod === "both") {
              // Placeholder for SMS integration
              console.log(`[SMS Placeholder] Would send SMS to ${userData.contactNumber} about ${vaccData.vaccineName}`);
            }

            // Log the reminder
            await db.collection("reminderLogs").add({
              userId,
              childId: childDoc.id,
              childName,
              vaccinationId: vaccDoc.id,
              vaccineName: vaccData.vaccineName,
              dose: vaccData.dose,
              dueDate,
              method: prefs.reminderMethod,
              status: result.sent ? "sent" : "failed",
              reason: result.reason || null,
              sentDate: today,
              sentAt: Date.now(),
            });

            remindersSent++;
            console.log(`Sent reminder for ${vaccData.vaccineName} to ${userData.email}`);
          }
        }
      }
    }

    console.log(`Reminder check complete. ${remindersSent} reminders processed.`);
    res.status(200).json({ message: `Reminder check complete. ${remindersSent} reminders processed.` });
  } catch (error) {
    console.error("Reminder check error:", error);
    res.status(500).json({ error: "Failed to process reminders." });
  }
});

// GET /api/parent/reminder-logs - Fetch reminder logs for the logged-in parent
app.get("/api/parent/reminder-logs", verifyIdToken, async (req, res) => {
  try {
    const userId = req.uid;

    // FIX: Removed .orderBy("sentAt", "desc") — requires a Firestore composite
    // index that may not exist. Sort in-memory instead.
    const logsSnapshot = await db
      .collection("reminderLogs")
      .where("userId", "==", userId)
      .get();

    const logs = [];
    logsSnapshot.forEach((doc) => {
      logs.push({ id: doc.id, ...doc.data() });
    });

    // Sort by sentAt descending (newest first) and limit to 50
    logs.sort((a, b) => (b.sentAt || 0) - (a.sentAt || 0));

    res.status(200).json(logs.slice(0, 50));
  } catch (error) {
    console.error("Fetch reminder logs error:", error);
    res.status(500).json({ error: "Failed to fetch reminder logs." });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// GLOBAL ERROR HANDLER & START
// ═══════════════════════════════════════════════════════════════════════════════

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  if (!res.headersSent) {
    res.status(500).json({ error: err.message || "Server error." });
  }
});

const PORT = process.env.PORT || 5502;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});