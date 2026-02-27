import { 
  createUserWithEmailAndPassword, 
  signInWithEmailAndPassword,
  signOut,
  updateProfile,
  updateEmail,
  updatePassword,
  reauthenticateWithCredential,
  EmailAuthProvider
} from 'firebase/auth';
import { 
  doc, 
  setDoc, 
  getDoc, 
  updateDoc,
  serverTimestamp,
  collection,
  query,
  where,
  getDocs
} from 'firebase/firestore';
import { auth, db } from '../config/firebase';

// Register new user
export const registerUser = async (username, email, password) => {
  // Check if username already exists
  const usernameQuery = query(collection(db, 'users'), where('username', '==', username));
  const usernameSnapshot = await getDocs(usernameQuery);
  
  if (!usernameSnapshot.empty) {
    throw new Error('Username already exists');
  }

  // Create auth user
  const userCredential = await createUserWithEmailAndPassword(auth, email, password);
  const user = userCredential.user;

  // Update display name
  await updateProfile(user, { displayName: username });

  // Create user document in Firestore
  await setDoc(doc(db, 'users', user.uid), {
    username,
    email,
    isAdmin: false,
    mfaEnabled: false,
    totpSecret: null,
    createdAt: serverTimestamp()
  });

  return {
    id: user.uid,
    username,
    email,
    isAdmin: false,
    mfaEnabled: false
  };
};

// Login user
export const loginUser = async (email, password) => {
  const userCredential = await signInWithEmailAndPassword(auth, email, password);
  const user = userCredential.user;

  // Get user data from Firestore
  const userDoc = await getDoc(doc(db, 'users', user.uid));
  
  if (!userDoc.exists()) {
    throw new Error('User data not found');
  }

  const userData = userDoc.data();

  return {
    id: user.uid,
    username: userData.username,
    email: userData.email,
    isAdmin: userData.isAdmin || false,
    mfaEnabled: userData.mfaEnabled || false,
    totpSecret: userData.totpSecret
  };
};

// Logout user
export const logoutUser = async () => {
  await signOut(auth);
};

// Get current user data
export const getCurrentUser = async (uid) => {
  const userDoc = await getDoc(doc(db, 'users', uid));
  
  if (!userDoc.exists()) {
    return null;
  }

  const userData = userDoc.data();
  
  return {
    id: uid,
    username: userData.username,
    email: userData.email,
    isAdmin: userData.isAdmin || false,
    mfaEnabled: userData.mfaEnabled || false,
    createdAt: userData.createdAt?.toDate()
  };
};

// Update user profile
export const updateUserProfile = async (uid, data) => {
  const { username, email, currentPassword, newPassword } = data;
  const user = auth.currentUser;

  if (!user) throw new Error('Not authenticated');

  // Update Firestore document
  const updateData = {};
  if (username) updateData.username = username;
  if (email && email !== user.email) {
    // Need to reauthenticate to change email
    if (!currentPassword) throw new Error('Current password required to change email');
    const credential = EmailAuthProvider.credential(user.email, currentPassword);
    await reauthenticateWithCredential(user, credential);
    await updateEmail(user, email);
    updateData.email = email;
  }

  if (Object.keys(updateData).length > 0) {
    await updateDoc(doc(db, 'users', uid), updateData);
  }

  // Update password if provided
  if (newPassword) {
    if (!currentPassword) throw new Error('Current password required');
    const credential = EmailAuthProvider.credential(user.email, currentPassword);
    await reauthenticateWithCredential(user, credential);
    await updatePassword(user, newPassword);
  }

  // Update display name
  if (username) {
    await updateProfile(user, { displayName: username });
  }

  return getCurrentUser(uid);
};

// Enable MFA
export const enableMFA = async (uid, secret) => {
  await updateDoc(doc(db, 'users', uid), {
    totpSecret: secret,
    mfaEnabled: true
  });
};

// Disable MFA
export const disableMFA = async (uid) => {
  await updateDoc(doc(db, 'users', uid), {
    totpSecret: null,
    mfaEnabled: false
  });
};

// Get user's TOTP secret
export const getTotpSecret = async (uid) => {
  const userDoc = await getDoc(doc(db, 'users', uid));
  if (!userDoc.exists()) return null;
  return userDoc.data().totpSecret;
};
