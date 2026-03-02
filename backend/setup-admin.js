// Setup script to add/verify admin user in Firestore
const admin = require("firebase-admin");
const serviceAccount = require("./firebaseServiceAccount.json");

// Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

async function setupAdmin() {
  try {
    const adminUid = "INyF8sEZ9QQYj5Srzw2xRDAERFh1";
    
    console.log(`Setting up admin user with UID: ${adminUid}`);
    
    // Check if user exists
    const userDoc = await db.collection("users").doc(adminUid).get();
    
    if (userDoc.exists) {
      console.log("Current user data:", userDoc.data());
      
      // Update user to have admin role
      await db.collection("users").doc(adminUid).update({
        role: "admin",
        updatedAt: new Date().getTime(),
      });
      
      console.log("✓ Admin role set successfully!");
    } else {
      console.log("User document does not exist. Creating new admin user...");
      
      // Create new admin user document
      await db.collection("users").doc(adminUid).set({
        firstName: "Dr.",
        lastName: "Reganion",
        email: "admin@reganion.com",
        contactNumber: "+63 919 555 0000",
        role: "admin",
        createdAt: new Date().getTime(),
      });
      
      console.log("✓ Admin user created with role set to 'admin'!");
    }
    
    // Verify the update
    const updated = await db.collection("users").doc(adminUid).get();
    console.log("\nVerification - Updated user data:");
    console.log(JSON.stringify(updated.data(), null, 2));
    
    process.exit(0);
  } catch (error) {
    console.error("Error setting up admin:", error);
    process.exit(1);
  }
}

setupAdmin();
