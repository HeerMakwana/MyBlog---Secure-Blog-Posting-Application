import { 
  collection, 
  doc, 
  addDoc, 
  getDoc, 
  getDocs, 
  updateDoc, 
  deleteDoc,
  query, 
  where, 
  orderBy,
  serverTimestamp 
} from 'firebase/firestore';
import { db } from '../config/firebase';

// Create slug from title
const createSlug = (title) => {
  const baseSlug = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/gi, '-')
    .replace(/^-|-$/g, '');
  const uniqueId = Math.random().toString(36).substring(2, 8);
  return `${baseSlug}-${uniqueId}`;
};

// Get all posts
export const getAllPosts = async () => {
  const postsQuery = query(
    collection(db, 'posts'),
    orderBy('createdAt', 'desc')
  );
  
  const snapshot = await getDocs(postsQuery);
  const posts = [];
  
  for (const postDoc of snapshot.docs) {
    const postData = postDoc.data();
    // Get user data
    const userDoc = await getDoc(doc(db, 'users', postData.userId));
    const userData = userDoc.exists() ? userDoc.data() : { username: 'Unknown' };
    
    posts.push({
      id: postDoc.id,
      ...postData,
      user: { id: postData.userId, username: userData.username },
      createdAt: postData.createdAt?.toDate(),
      updatedAt: postData.updatedAt?.toDate()
    });
  }
  
  return posts;
};

// Get user's posts
export const getUserPosts = async (userId) => {
  const postsQuery = query(
    collection(db, 'posts'),
    where('userId', '==', userId),
    orderBy('createdAt', 'desc')
  );
  
  const snapshot = await getDocs(postsQuery);
  
  return snapshot.docs.map(postDoc => ({
    id: postDoc.id,
    ...postDoc.data(),
    createdAt: postDoc.data().createdAt?.toDate(),
    updatedAt: postDoc.data().updatedAt?.toDate()
  }));
};

// Get post by slug
export const getPostBySlug = async (slug) => {
  const postsQuery = query(
    collection(db, 'posts'),
    where('slug', '==', slug)
  );
  
  const snapshot = await getDocs(postsQuery);
  
  if (snapshot.empty) {
    return null;
  }
  
  const postDoc = snapshot.docs[0];
  const postData = postDoc.data();
  
  // Get user data
  const userDoc = await getDoc(doc(db, 'users', postData.userId));
  const userData = userDoc.exists() ? userDoc.data() : { username: 'Unknown' };
  
  return {
    id: postDoc.id,
    ...postData,
    user: { id: postData.userId, username: userData.username },
    createdAt: postData.createdAt?.toDate(),
    updatedAt: postData.updatedAt?.toDate()
  };
};

// Get post by ID
export const getPostById = async (postId) => {
  const postDoc = await getDoc(doc(db, 'posts', postId));
  
  if (!postDoc.exists()) {
    return null;
  }
  
  const postData = postDoc.data();
  
  return {
    id: postDoc.id,
    ...postData,
    createdAt: postData.createdAt?.toDate(),
    updatedAt: postData.updatedAt?.toDate()
  };
};

// Create post
export const createPost = async (userId, title, body, imageUrl = null) => {
  const slug = createSlug(title);
  
  const postRef = await addDoc(collection(db, 'posts'), {
    userId,
    title,
    slug,
    body,
    imagePath: imageUrl, // Use external image URL instead of uploaded file
    createdAt: serverTimestamp(),
    updatedAt: null
  });
  
  return {
    id: postRef.id,
    slug,
    title,
    body,
    imagePath: imageUrl
  };
};

// Update post
export const updatePost = async (postId, userId, title, body, isAdmin = false) => {
  const postDoc = await getDoc(doc(db, 'posts', postId));
  
  if (!postDoc.exists()) {
    throw new Error('Post not found');
  }
  
  const postData = postDoc.data();
  
  // Check ownership
  if (postData.userId !== userId && !isAdmin) {
    throw new Error('Not authorized to update this post');
  }
  
  const slug = createSlug(title);
  
  await updateDoc(doc(db, 'posts', postId), {
    title,
    slug,
    body,
    updatedAt: serverTimestamp()
  });
  
  return { id: postId, slug, title, body };
};

// Delete post
export const deletePost = async (postId, userId, isAdmin = false) => {
  const postDoc = await getDoc(doc(db, 'posts', postId));
  
  if (!postDoc.exists()) {
    throw new Error('Post not found');
  }
  
  const postData = postDoc.data();
  
  // Check ownership
  if (postData.userId !== userId && !isAdmin) {
    throw new Error('Not authorized to delete this post');
  }
  
  await deleteDoc(doc(db, 'posts', postId));
};
