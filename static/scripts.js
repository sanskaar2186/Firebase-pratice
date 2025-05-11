// Firebase configuration (replace with your actual config)
const firebaseConfig = {
  apiKey: "AIzaSyAti6Wr8K7d9W-7nchnLm-XM-TsoQjNJTY",
  authDomain: "fir-pra-bec88.firebaseapp.com",
  projectId: "fir-pra-bec88",
  storageBucket: "fir-pra-bec88.firebasestorage.app",
  messagingSenderId: "947761646740",
  appId: "1:947761646740:web:6201b8b1c06a1ffd6e3881",
  measurementId: "G-2W2BLK9QEZ"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();

// Google Auth Provider
const googleProvider = new firebase.auth.GoogleAuthProvider();

// Handle Google Sign In/Up
async function handleGoogleAuth() {
    try {
        console.log("Starting Google authentication");
        const result = await auth.signInWithPopup(googleProvider);
        console.log("Google auth successful:", result);
        
        const token = await result.user.getIdToken();
        console.log("Got ID token, sending to backend");
        
        // Send token to backend
        const response = await fetch('/api/verify-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token })
        });
        
        console.log("Backend response:", response.status);
        if (response.ok) {
            console.log("Google auth successful, redirecting to dashboard");
            window.location.href = '/dashboard';
        } else {
            const errorData = await response.json();
            console.error("Backend error:", errorData);
            alert("Authentication failed: " + (errorData.error || "Unknown error"));
        }
    } catch (error) {
        console.error("Google auth error details:", error);
        alert("Google authentication failed: " + error.message);
    }
}

// Add Google auth handlers
document.getElementById('googleLogin')?.addEventListener('click', handleGoogleAuth);
document.getElementById('googleRegister')?.addEventListener('click', handleGoogleAuth);

// Login function
document.getElementById("loginForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("loginEmail").value;
  const password = document.getElementById("loginPassword").value;

  try {
    console.log("Attempting login with:", email);
    const userCredential = await auth.signInWithEmailAndPassword(
      email,
      password
    );
    console.log("Firebase login successful:", userCredential);
    const token = await userCredential.user.getIdToken();
    console.log("Got ID token, sending to backend");

    // Send token to backend
    const response = await fetch("/api/verify-token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ token }),
    });

    console.log("Backend response:", response.status);
    if (response.ok) {
      console.log("Login successful, redirecting to dashboard");
      window.location.href = "/dashboard";
    } else {
      const errorData = await response.json();
      console.error("Backend error:", errorData);
      alert("Login failed: " + (errorData.error || "Unknown error"));
    }
  } catch (error) {
    console.error("Login error details:", error);
    alert("Login failed: " + error.message);
  }
});

// Registration function
document.getElementById('registerForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('registerEmail').value;
    const password = document.getElementById('registerPassword').value;
    
    try {
        console.log("Attempting registration with:", email);
        const userCredential = await auth.createUserWithEmailAndPassword(email, password);
        console.log("Firebase registration successful:", userCredential);
        const token = await userCredential.user.getIdToken();
        console.log("Got ID token, sending to backend");
        
        // Send token to backend
        const response = await fetch('/api/verify-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token })
        });
        
        console.log("Backend response:", response.status);
        if (response.ok) {
            console.log("Registration successful, redirecting to dashboard");
            window.location.href = '/dashboard';
        } else {
            const errorData = await response.json();
            console.error("Backend error:", errorData);
            alert("Registration failed: " + (errorData.error || "Unknown error"));
        }
    } catch (error) {
        console.error("Registration error details:", error);
        alert("Registration failed: " + error.message);
    }
});

// Dashboard functionality
document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on the dashboard
    if (window.location.pathname === '/dashboard') {
        console.log('Dashboard loaded');
        
        // Example: Fetch additional user data
        firebase.auth().onAuthStateChanged((user) => {
            if (user) {
                console.log('User is signed in:', user);
            } else {
                console.log('No user signed in, redirecting to login');
                window.location.href = '/login';
            }
        });
    }
});



// Password Reset Handler
function handlePasswordReset(email) {
  firebase.auth().sendPasswordResetEmail(email)
      .then(() => {
          alert('Password reset email sent!');
      })
      .catch(error => {
          console.error('Reset error:', error);
          alert(error.message);
      });
}

// Profile Photo Upload (Example)
function uploadProfilePhoto(file) {
  const storageRef = firebase.storage().ref();
  const uploadTask = storageRef.child(`profile_photos/${session.user.uid}`).put(file);
  
  uploadTask.on('state_changed', 
      (snapshot) => {
          // Progress monitoring
          const progress = (snapshot.bytesTransferred / snapshot.totalBytes) * 100;
          console.log('Upload progress: ' + progress + '%');
      },
      (error) => {
          alert('Upload failed: ' + error.message);
      },
      () => {
          uploadTask.snapshot.ref.getDownloadURL().then((downloadURL) => {
              document.querySelector('input[name="photo_url"]').value = downloadURL;
          });
      }
  );
}


// Highlight active page in navigation
document.querySelectorAll('.nav-links a').forEach(link => {
  if (link.href === window.location.href) {
      link.classList.add('active-nav-link');
  }
});