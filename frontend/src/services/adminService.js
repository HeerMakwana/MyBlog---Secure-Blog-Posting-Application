import { 
  collection, 
  doc, 
  getDoc, 
  getDocs, 
  deleteDoc,
  query, 
  orderBy,
  where
} from 'firebase/firestore';
import { db } from '../config/firebase';
import { deletePost } from './postService';

// Get all users (admin only)
export const getAllUsers = async () => {
  const usersQuery = query(
    collection(db, 'users'),
    orderBy('createdAt', 'desc')
  );
  
  const snapshot = await getDocs(usersQuery);
  
  return snapshot.docs.map(userDoc => ({
    id: userDoc.id,
    ...userDoc.data(),
    createdAt: userDoc.data().createdAt?.toDate()
  }));
};

// Delete user and their posts (admin only)
export const deleteUser = async (userId, adminId) => {
  if (userId === adminId) {
    throw new Error('Cannot delete your own account');
  }
  
  // Delete all user's posts
  const postsQuery = query(
    collection(db, 'posts'),
    where('userId', '==', userId)
  );
  
  const postsSnapshot = await getDocs(postsQuery);
  
  for (const postDoc of postsSnapshot.docs) {
    await deletePost(postDoc.id, userId, true);
  }
  
  // Delete user document
  await deleteDoc(doc(db, 'users', userId));
};

// Get admin stats
export const getAdminStats = async () => {
  const usersSnapshot = await getDocs(collection(db, 'users'));
  const postsSnapshot = await getDocs(collection(db, 'posts'));
  
  // Get recent users
  const recentUsersQuery = query(
    collection(db, 'users'),
    orderBy('createdAt', 'desc')
  );
  const recentUsersSnapshot = await getDocs(recentUsersQuery);
  const recentUsers = recentUsersSnapshot.docs.slice(0, 5).map(doc => ({
    id: doc.id,
    ...doc.data(),
    createdAt: doc.data().createdAt?.toDate()
  }));
  
  // Get recent posts with user data
  const recentPostsQuery = query(
    collection(db, 'posts'),
    orderBy('createdAt', 'desc')
  );
  const recentPostsSnapshot = await getDocs(recentPostsQuery);
  const recentPosts = [];
  
  for (const postDoc of recentPostsSnapshot.docs.slice(0, 5)) {
    const postData = postDoc.data();
    const userDoc = await getDoc(doc(db, 'users', postData.userId));
    const userData = userDoc.exists() ? userDoc.data() : { username: 'Unknown' };
    
    recentPosts.push({
      id: postDoc.id,
      ...postData,
      user: { username: userData.username },
      createdAt: postData.createdAt?.toDate()
    });
  }
  
  return {
    totalUsers: usersSnapshot.size,
    totalPosts: postsSnapshot.size,
    recentUsers,
    recentPosts
  };
};

// Get all posts (admin)
export const getAllPostsAdmin = async () => {
  const postsQuery = query(
    collection(db, 'posts'),
    orderBy('createdAt', 'desc')
  );
  
  const snapshot = await getDocs(postsQuery);
  const posts = [];
  
  for (const postDoc of snapshot.docs) {
    const postData = postDoc.data();
    const userDoc = await getDoc(doc(db, 'users', postData.userId));
    const userData = userDoc.exists() ? userDoc.data() : { username: 'Unknown' };
    
    posts.push({
      id: postDoc.id,
      ...postData,
      user: { id: postData.userId, username: userData.username },
      createdAt: postData.createdAt?.toDate()
    });
  }
  
  return posts;
};
